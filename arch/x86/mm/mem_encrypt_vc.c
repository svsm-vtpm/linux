// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#define DISABLE_BRANCH_PROFILING

#include <stdarg.h>

#include <linux/mem_encrypt.h>
#include <linux/percpu-defs.h>
#include <linux/printk.h>
#include <linux/context_tracking.h>

#include <asm/mem_encrypt_vc.h>
#include <asm/set_memory.h>
#include <asm/svm.h>
#include <asm/msr-index.h>
#include <asm/traps.h>

typedef int (*vmg_nae_exit_t)(struct ghcb *ghcb, unsigned long ghcb_pa,
			      struct pt_regs *regs, struct insn *insn);

static DEFINE_PER_CPU_DECRYPTED(struct ghcb, ghcb_page) __aligned(PAGE_SIZE);

static struct ghcb *early_ghcb_va;

static void vmg_exception(unsigned int excp)
{
	switch (excp) {
	case X86_TRAP_GP:
	case X86_TRAP_UD:
		break;
	default:
		WARN(1, "vmgexit exception is not valid (%u)\n", excp);
	}
}

static int vmg_exit(struct ghcb *ghcb, u64 exit_code,
		    u64 exit_info_1, u64 exit_info_2)
{
	unsigned int action, reason;

	ghcb->save.sw_exit_code = exit_code;
	ghcb->save.sw_exit_info_1 = exit_info_1;
	ghcb->save.sw_exit_info_2 = exit_info_2;

	/* VMGEXIT instruction */
	asm volatile ("rep; vmmcall" ::: "memory");

	if (!ghcb->save.sw_exit_info_1)
		return 0;

	reason = upper_32_bits(ghcb->save.sw_exit_info_1);
	action = lower_32_bits(ghcb->save.sw_exit_info_1);

	switch (action) {
	case 1:
		vmg_exception(reason);
		break;
	default:
		WARN(1, "vmgexit action is not valid (%u)\n", action);
	}

	return reason;
}

static unsigned long vc_start(struct ghcb *ghcb)
{
	unsigned long flags;

	local_irq_save(flags);
	preempt_disable();

	memset(&ghcb->save, 0, sizeof(ghcb->save));

	ghcb->protocol_version = GHCB_VERSION_MAX;
	ghcb->ghcb_usage = GHCB_USAGE_STANDARD;

	return flags;
}

static void vc_finish(struct ghcb *ghcb, unsigned long flags)
{
	local_irq_restore(flags);
	preempt_enable();
}

static long *vmg_insn_register(struct pt_regs *regs, u8 reg)
{
	switch (reg) {
	case 0:		return &regs->ax;
	case 1:		return &regs->cx;
	case 2:		return &regs->dx;
	case 3:		return &regs->bx;
	case 4:		return &regs->sp;
	case 5:		return &regs->bp;
	case 6:		return &regs->si;
	case 7:		return &regs->di;
	case 8:		return &regs->r8;
	case 9:		return &regs->r9;
	case 10:	return &regs->r10;
	case 11:	return &regs->r11;
	case 12:	return &regs->r12;
	case 13:	return &regs->r13;
	case 14:	return &regs->r14;
	case 15:	return &regs->r15;

	/* Should never get here */
	default:	return NULL;
	}
}

static phys_addr_t vmg_slow_virt_to_phys(struct ghcb *ghcb, long vaddr)
{
	unsigned long va = (unsigned long)vaddr;
	unsigned int level;
	phys_addr_t pa;
	pgd_t *pgd;
	pte_t *pte;

	pgd = pgd_offset(current->active_mm, va);
	pte = lookup_address_in_pgd(pgd, va, &level);
	if (!pte)
		return 0;

	pa = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
	pa |= va & ~page_level_mask(level);

	return pa;
}

static long vmg_insn_rmdata(struct insn *insn, struct pt_regs *regs)
{
	long effective_addr;
	u8 mod, rm;

	if (!insn->modrm.nbytes)
		return 0;

	if (insn_rip_relative(insn))
		return regs->ip + insn->displacement.value;

	mod = X86_MODRM_MOD(insn->modrm.value);
	rm = X86_MODRM_RM(insn->modrm.value);

	if (insn->rex_prefix.nbytes && X86_REX_B(insn->rex_prefix.value))
		rm |= 0x8;

	if (mod == 3)
		return *vmg_insn_register(regs, rm);

	effective_addr = 0;

	switch (mod) {
	case 1:
	case 2:
		effective_addr += insn->displacement.value;
		break;
	}

	if (insn->sib.nbytes) {
		u8 scale, index, base;

		scale = X86_SIB_SCALE(insn->sib.value);
		index = X86_SIB_INDEX(insn->sib.value);
		base = X86_SIB_BASE(insn->sib.value);
		if (insn->rex_prefix.nbytes &&
		    X86_REX_X(insn->rex_prefix.value))
			index |= 0x8;
		if (insn->rex_prefix.nbytes &&
		    X86_REX_B(insn->rex_prefix.value))
			base |= 0x8;

		if (index != 4)
			effective_addr += (*vmg_insn_register(regs, index) << scale);

		if ((base != 5) || mod)
			effective_addr += *vmg_insn_register(regs, base);
		else
			effective_addr += insn->displacement.value;
	} else {
		effective_addr += *vmg_insn_register(regs, rm);
	}

	return effective_addr;
}

static long *vmg_insn_regdata(struct insn *insn, struct pt_regs *regs)
{
	u8 reg;

	if (!insn->modrm.nbytes)
		return 0;

	reg = X86_MODRM_REG(insn->modrm.value);
	if (insn->rex_prefix.nbytes && X86_REX_R(insn->rex_prefix.value))
		reg |= 0x8;

	return vmg_insn_register(regs, reg);
}

static void vmg_insn_init(struct insn *insn, char *insn_buffer,
			  unsigned long ip)
{
	int insn_len, bytes_rem;

	if (ip > TASK_SIZE) {
		insn_buffer = (void *)ip;
		insn_len = MAX_INSN_SIZE;
	} else {
		bytes_rem = copy_from_user(insn_buffer, (const void __user *)ip,
					   MAX_INSN_SIZE);
		insn_len = MAX_INSN_SIZE - bytes_rem;
	}

	insn_init(insn, insn_buffer, insn_len, true);

	/* Parse the full instruction */
	insn_get_length(insn);

	/*
	 * Error checking?
	 *   If insn->immediate.got is not set after insn_get_length() then
	 *   the parsing failed at some point.
	 */
}

static int vmg_mmio(struct ghcb *ghcb, unsigned long ghcb_pa,
		    struct pt_regs *regs, struct insn *insn)
{
	u64 exit_info_1, exit_info_2;
	unsigned int bytes;
	long *reg_data;
	int ret;

	bytes = 0;

	switch (insn->opcode.bytes[0]) {
	/* MMIO Write */
	case 0x88:
		bytes = 1;
		/* Fallthrough */
	case 0x89:
		bytes = bytes ? bytes : insn->opnd_bytes;

		/* Register-direct addressing mode not supported with MMIO */
		if (X86_MODRM_MOD(insn->modrm.value) == 3) {
			ret = vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
				       SVM_EXIT_NPF, 0);
			return ret;
		}

		reg_data = vmg_insn_regdata(insn, regs);
		exit_info_1 = vmg_insn_rmdata(insn, regs);
		exit_info_1 = vmg_slow_virt_to_phys(ghcb, exit_info_1);
		exit_info_2 = bytes;

		memcpy(ghcb->shared_buffer, reg_data, bytes);
		ghcb->save.sw_scratch = ghcb_pa +
					offsetof(struct ghcb, shared_buffer);
		ret = vmg_exit(ghcb, SVM_VMGEXIT_MMIO_WRITE,
			       exit_info_1, exit_info_2);
		break;
	/* MMIO Read */
	case 0x8a:
		bytes = 1;
		/* Fallthrough */
	case 0x8b:
		bytes = bytes ? bytes : insn->opnd_bytes;

		/* Register-direct addressing mode not supported with MMIO */
		if (X86_MODRM_MOD(insn->modrm.value) == 3) {
			ret = vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
				       SVM_EXIT_NPF, 0);
			return ret;
		}

		reg_data = vmg_insn_regdata(insn, regs);
		exit_info_1 = vmg_insn_rmdata(insn, regs);
		exit_info_1 = vmg_slow_virt_to_phys(ghcb, exit_info_1);
		exit_info_2 = bytes;

		ghcb->save.sw_scratch = ghcb_pa +
					offsetof(struct ghcb, shared_buffer);
		ret = vmg_exit(ghcb, SVM_VMGEXIT_MMIO_READ,
			       exit_info_1, exit_info_2);
		if (ret)
			break;

		if (bytes == 4)
			*reg_data = 0;	/* Zero-extend for 32-bit operation */

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;
	default:
		ret = vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
			       SVM_EXIT_NPF, 0);
	}

	return ret;
}

static int sev_es_vc_exception(struct pt_regs *regs, long error_code)
{
	char insn_buffer[MAX_INSN_SIZE];
	vmg_nae_exit_t nae_exit = NULL;
	enum ctx_state prev_state;
	unsigned long ghcb_pa;
	unsigned long flags;
	struct ghcb *ghcb;
	struct insn insn;
	int ret;

	prev_state = exception_enter();

	ghcb_pa = native_read_msr(MSR_AMD64_SEV_GHCB);
	if (!ghcb_pa ||
	    ((ghcb_pa & GHCB_MSR_INFO_MASK) == GHCB_MSR_SEV_INFO_RESP)) {
		/* GHCB not yet established, so set it up */
		ghcb_pa = __pa(this_cpu_ptr(&ghcb_page));
		native_wrmsrl(MSR_AMD64_SEV_GHCB, ghcb_pa);
	}

	/* Get the proper GHCB virtual address to use */
	if (ghcb_pa == __pa(early_ghcb)) {
		ghcb = early_ghcb_va;
	} else {
		WARN_ONCE(ghcb_pa != __pa(this_cpu_ptr(&ghcb_page)),
			  "GHCB MSR value was not what was expected\n");

		ghcb = this_cpu_ptr(&ghcb_page);
	}

	flags = vc_start(ghcb);

	switch (error_code) {
	case SVM_EXIT_NPF:
		nae_exit = vmg_mmio;
		break;
	default:
		ret = vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
			       error_code, 0);
	}

	if (nae_exit) {
		vmg_insn_init(&insn, insn_buffer, regs->ip);
		ret = nae_exit(ghcb, ghcb_pa, regs, &insn);
		if (!ret)
			regs->ip += insn.length;
	}

	vc_finish(ghcb, flags);

	exception_exit(prev_state);

	return ret;
}

dotraplinkage void do_vmm_communication(struct pt_regs *regs, long error_code)
{
	int ret;

	ret = sev_es_vc_exception(regs, error_code);
	if (!ret)
		return;

	switch (ret) {
	case X86_TRAP_GP:
		do_general_protection(regs, 0);
		break;
	case X86_TRAP_UD:
		do_invalid_op(regs, 0);
		break;
	}
}

void __init early_ghcb_init(void)
{
	unsigned long early_ghcb_pa;

	if (!sev_es_active())
		return;

	early_ghcb_pa = __pa(early_ghcb);
	early_ghcb_va = early_memremap_decrypted(early_ghcb_pa, PAGE_SIZE);
	BUG_ON(!early_ghcb_va);

	memset(early_ghcb_va, 0, PAGE_SIZE);

	native_wrmsrl(MSR_AMD64_SEV_GHCB, early_ghcb_pa);
}

void __init ghcb_init(void)
{
	int cpu;

	if (!sev_es_active())
		return;

	for_each_possible_cpu(cpu) {
		struct ghcb *ghcb = &per_cpu(ghcb_page, cpu);

		set_memory_decrypted((unsigned long)ghcb,
				     sizeof(ghcb_page) >> PAGE_SHIFT);
		memset(ghcb, 0, sizeof(*ghcb));
	}

	/*
	 * Switch the BSP over from the early GHCB page to the per-CPU GHCB
	 * page and un-map the early mapping.
	 */
	native_wrmsrl(MSR_AMD64_SEV_GHCB, __pa(this_cpu_ptr(&ghcb_page)));

	early_memunmap(early_ghcb_va, PAGE_SIZE);
}
