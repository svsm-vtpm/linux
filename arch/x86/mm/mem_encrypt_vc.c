/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2018 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define DISABLE_BRANCH_PROFILING

#include <stdarg.h>

#include <linux/mem_encrypt.h>
#include <linux/percpu-defs.h>
#include <linux/printk.h>

#include <asm/mem_encrypt_vc.h>
#include <asm/set_memory.h>
#include <asm/svm.h>
#include <asm/msr-index.h>
#include <asm/traps.h>

static DEFINE_PER_CPU_DECRYPTED(struct ghcb, ghcb_page) __aligned(PAGE_SIZE);
static DEFINE_PER_CPU(struct insn, vc_insn);
static DEFINE_PER_CPU(char, vc_insn_buffer[MAX_INSN_SIZE]);

static struct ghcb *early_ghcb_va;
static struct insn early_vc_insn;
static char early_vc_insn_buffer[MAX_INSN_SIZE];

static void vmg_exception(unsigned int excp)
{
	switch (excp) {
	case X86_TRAP_GP:
	case X86_TRAP_UD:
		break;
	default:
		BUG();
	}
}

static int vmg_exit(struct ghcb *ghcb, u64 exit_code,
		    u64 exit_info_1, u64 exit_info_2)
{
	unsigned int action, reason;

	ghcb->save.sw_exit_code = exit_code;
	ghcb->save.sw_exit_info_1 = exit_info_1;
	ghcb->save.sw_exit_info_2 = exit_info_2;

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
		BUG();
	}

	return reason;
}

static unsigned long vmg_init(struct ghcb *ghcb)
{
	unsigned long flags;

	local_irq_save(flags);
	preempt_disable();

	memset(&ghcb->save, 0, sizeof(ghcb->save));

	ghcb->protocol_version = GHCB_VERSION_MAX;
	ghcb->ghcb_usage = GHCB_USAGE_STANDARD;

	return flags;
}

static void vmg_done(struct ghcb *ghcb, unsigned long flags)
{
	local_irq_restore(flags);
	preempt_enable();
}

static long *vmg_insn_register(struct pt_regs *regs, u8 reg)
{
	switch (reg) {
	case 0:		return &regs->ax;
	case 1:		return &regs->cx;
	case 2: 	return &regs->dx;
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
		if (insn->rex_prefix.nbytes && X86_REX_X(insn->rex_prefix.value))
			index |= 0x8;
		if (insn->rex_prefix.nbytes && X86_REX_B(insn->rex_prefix.value))
			base |= 0x8;

		if (index != 4)
			effective_addr += (*vmg_insn_register(regs, index) << scale);

		if ((base != 5) || mod)
			effective_addr += *vmg_insn_register(regs, base);
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
		bytes_rem = copy_from_user(insn_buffer, (const void __user *)ip, MAX_INSN_SIZE);
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
		ret = vmg_exit(ghcb, SVM_VMGEXIT_MMIO_WRITE, exit_info_1, exit_info_2);
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
		ret = vmg_exit(ghcb, SVM_VMGEXIT_MMIO_READ, exit_info_1, exit_info_2);
		if (ret)
			break;

		if (bytes == 4)
			*reg_data = 0;	/* Zero-extend for 32-bit operation */

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;
	default:
		ret = vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT, SVM_EXIT_NPF, 0);
	}

	return ret;
}

int sev_es_vc_exception(struct pt_regs *regs, long error_code)
{
	enum ctx_state prev_state;
	unsigned long ghcb_pa;
	unsigned long flags;
	struct ghcb *ghcb;
	struct insn *insn;
	char *insn_buffer;
	int ret;

	prev_state = exception_enter();

	ghcb_pa = native_read_msr(MSR_AMD64_SEV_GHCB);
	if (!ghcb_pa || ghcb_pa & 1) {
		ghcb_pa = __pa(this_cpu_ptr(&ghcb_page));
		native_wrmsrl(MSR_AMD64_SEV_GHCB, ghcb_pa);
	}

	if (ghcb_pa == __pa(early_ghcb)) {
		ghcb = early_ghcb_va;
		insn = &early_vc_insn;
		insn_buffer = early_vc_insn_buffer;
	} else if (ghcb_pa == __pa(this_cpu_ptr(&ghcb_page))) {
		ghcb = this_cpu_ptr(&ghcb_page);
		insn = this_cpu_ptr(&vc_insn);
		insn_buffer = this_cpu_ptr(vc_insn_buffer);
	} else {
		BUG();
	}

	flags = vmg_init(ghcb);

	switch (error_code) {
	case SVM_EXIT_NPF:
		vmg_insn_init(insn, insn_buffer, regs->ip);
		ret = vmg_mmio(ghcb, ghcb_pa, regs, insn);
		if (ret)
			break;

		regs->ip += insn->length;
		break;
	default:
		ret = vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT, error_code, 0);
	}

	vmg_done(ghcb, flags);

	exception_exit(prev_state);

	return ret;
}

void __init early_ghcb_init(void)
{
	unsigned long early_ghcb_pa = __pa(early_ghcb);

	if (!sev_es_active())
		return;

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

		set_memory_decrypted((unsigned long)ghcb, 1);
		memset(ghcb, 0, PAGE_SIZE);
	}

	native_wrmsrl(MSR_AMD64_SEV_GHCB, __pa(this_cpu_ptr(&ghcb_page)));

	early_memunmap(early_ghcb_va, PAGE_SIZE);
}
