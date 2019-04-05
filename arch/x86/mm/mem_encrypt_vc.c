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

static struct ghcb *early_ghcb_va;

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

int sev_es_vc_exception(struct pt_regs *regs, long error_code)
{
	enum ctx_state prev_state;
	unsigned long ghcb_pa;
	unsigned long flags;
	struct ghcb *ghcb;
	int ret;

	prev_state = exception_enter();

	ghcb_pa = native_read_msr(MSR_AMD64_SEV_GHCB);
	if (!ghcb_pa || ghcb_pa & 1) {
		ghcb_pa = __pa(this_cpu_ptr(&ghcb_page));
		native_wrmsrl(MSR_AMD64_SEV_GHCB, ghcb_pa);
	}

	if (ghcb_pa == __pa(early_ghcb))
		ghcb = early_ghcb_va;
	else if (ghcb_pa == __pa(this_cpu_ptr(&ghcb_page)))
		ghcb = this_cpu_ptr(&ghcb_page);
	else
		BUG();

	flags = vmg_init(ghcb);

	switch (error_code) {
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
