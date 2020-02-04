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

static DEFINE_PER_CPU_DECRYPTED(struct ghcb, ghcb_page) __aligned(PAGE_SIZE);

static struct ghcb *early_ghcb_va;

static u64 vmg_unsupported_event(void)
{
	u64 event;

	event = X86_TRAP_GP | SVM_EVTINJ_TYPE_EXEPT | SVM_EVTINJ_VALID;

	return event;
}

static u64 vmg_exception(u64 excp)
{
	if ((excp & SVM_EVTINJ_TYPE_MASK) != SVM_EVTINJ_TYPE_EXEPT)
		return vmg_unsupported_event();

	if (!(excp & SVM_EVTINJ_VALID))
		return vmg_unsupported_event();

	switch (excp & SVM_EVTINJ_VEC_MASK) {
	case X86_TRAP_GP:
	case X86_TRAP_UD:
		return excp;
	default:
		return vmg_unsupported_event();
	}
}

static u64 vmg_error_check(struct ghcb *ghcb)
{
	unsigned int action;

	action = lower_32_bits(ghcb->save.sw_exit_info_1);
	switch (action) {
	case 0:
		return 0;
	case 1:
		return vmg_exception(ghcb->save.sw_exit_info_2);
	default:
		return vmg_unsupported_event();
	}
}

static u64 vmg_exit(struct ghcb *ghcb, u64 exit_code,
		    u64 exit_info_1, u64 exit_info_2)
{
	ghcb->save.sw_exit_code = exit_code;
	ghcb->save.sw_exit_info_1 = exit_info_1;
	ghcb->save.sw_exit_info_2 = exit_info_2;

	/* VMGEXIT instruction */
	asm volatile ("rep; vmmcall" ::: "memory");

	return vmg_error_check(ghcb);
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

static u64 sev_es_vc_exception(struct pt_regs *regs, long error_code)
{
	enum ctx_state prev_state;
	unsigned long ghcb_pa;
	unsigned long flags;
	struct ghcb *ghcb;
	u64 ret;

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
	default:
		ret = vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
			       error_code, 0);
		if (!ret)
			ret = vmg_unsupported_event();
	}

	vc_finish(ghcb, flags);

	exception_exit(prev_state);

	return ret;
}

dotraplinkage void do_vmm_communication(struct pt_regs *regs, long error_code)
{
	u64 ret;

	ret = sev_es_vc_exception(regs, error_code);
	if (!ret)
		return;

	error_code = (ret & SVM_EVTINJ_VALID_ERR) ? upper_32_bits(ret) : 0;

	switch (ret & SVM_EVTINJ_VEC_MASK) {
	case X86_TRAP_GP:
		do_general_protection(regs, error_code);
		break;
	case X86_TRAP_UD:
		do_invalid_op(regs, error_code);
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
