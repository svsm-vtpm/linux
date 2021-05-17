// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 SUSE
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#define pr_fmt(fmt)	"SEV-ES: " fmt

#include <linux/platform_device.h>
#include <linux/sched/debug.h>	/* For show_regs() */
#include <linux/percpu-defs.h>
#include <linux/mem_encrypt.h>
#include <linux/lockdep.h>
#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/set_memory.h>
#include <linux/sev-guest.h>
#include <linux/memblock.h>
#include <linux/kernel.h>
#include <linux/efi.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include <linux/io.h>
#include <linux/io.h>
#include <linux/iommu.h>

#include <asm/cpu_entry_area.h>
#include <asm/stacktrace.h>
#include <asm/sev.h>
#include <asm/insn-eval.h>
#include <asm/fpu/internal.h>
#include <asm/processor.h>
#include <asm/realmode.h>
#include <asm/traps.h>
#include <asm/svm.h>
#include <asm/smp.h>
#include <asm/cpu.h>
#include <asm/apic.h>
#include <asm/setup.h>		/* For struct boot_params */
#include <asm/iommu.h>

#include "sev-internal.h"

#define DR7_RESET_VALUE        0x400

#define RMPTABLE_ENTRIES_OFFSET	0x4000
#define RMPENTRY_SHIFT		8
#define rmptable_page_offset(x)	(RMPTABLE_ENTRIES_OFFSET + (((unsigned long)x) >> RMPENTRY_SHIFT))

/* For early boot hypervisor communication in SEV-ES enabled guests */
static struct ghcb boot_ghcb_page __bss_decrypted __aligned(PAGE_SIZE);

/*
 * Needs to be in the .data section because we need it NULL before bss is
 * cleared
 */
static struct ghcb __initdata *boot_ghcb;

static unsigned long snp_secrets_phys;

static unsigned long rmptable_start __ro_after_init;
static unsigned long rmptable_end __ro_after_init;

/* #VC handler runtime per-CPU data */
struct sev_es_runtime_data {
	struct ghcb ghcb_page;

	/* Physical storage for the per-CPU IST stack of the #VC handler */
	char ist_stack[EXCEPTION_STKSZ] __aligned(PAGE_SIZE);

	/*
	 * Physical storage for the per-CPU fall-back stack of the #VC handler.
	 * The fall-back stack is used when it is not safe to switch back to the
	 * interrupted stack in the #VC entry code.
	 */
	char fallback_stack[EXCEPTION_STKSZ] __aligned(PAGE_SIZE);

	/*
	 * Reserve one page per CPU as backup storage for the unencrypted GHCB.
	 * It is needed when an NMI happens while the #VC handler uses the real
	 * GHCB, and the NMI handler itself is causing another #VC exception. In
	 * that case the GHCB content of the first handler needs to be backed up
	 * and restored.
	 */
	struct ghcb backup_ghcb;

	/*
	 * Mark the per-cpu GHCBs as in-use to detect nested #VC exceptions.
	 * There is no need for it to be atomic, because nothing is written to
	 * the GHCB between the read and the write of ghcb_active. So it is safe
	 * to use it when a nested #VC exception happens before the write.
	 *
	 * This is necessary for example in the #VC->NMI->#VC case when the NMI
	 * happens while the first #VC handler uses the GHCB. When the NMI code
	 * raises a second #VC handler it might overwrite the contents of the
	 * GHCB written by the first handler. To avoid this the content of the
	 * GHCB is saved and restored when the GHCB is detected to be in use
	 * already.
	 */
	bool ghcb_active;
	bool backup_ghcb_active;

	/*
	 * Cached DR7 value - write it on DR7 writes and return it on reads.
	 * That value will never make it to the real hardware DR7 as debugging
	 * is currently unsupported in SEV-ES guests.
	 */
	unsigned long dr7;

	/*
	 * SEV-SNP requires that the GHCB must be registered before using it.
	 * The flag below will indicate whether the GHCB is registered, if its
	 * not registered then sev_es_get_ghcb() will perform the registration.
	 */
	bool snp_ghcb_registered;
};

struct ghcb_state {
	struct ghcb *ghcb;
};

#ifdef CONFIG_EFI
extern unsigned long cc_blob_phys;
#endif

static DEFINE_PER_CPU(struct sev_es_runtime_data*, runtime_data);
DEFINE_STATIC_KEY_FALSE(sev_es_enable_key);

static DEFINE_PER_CPU(struct sev_es_save_area *, snp_vmsa);

/* Needed in vc_early_forward_exception */
void do_early_exception(struct pt_regs *regs, int trapnr);

static void __init setup_vc_stacks(int cpu)
{
	struct sev_es_runtime_data *data;
	struct cpu_entry_area *cea;
	unsigned long vaddr;
	phys_addr_t pa;

	data = per_cpu(runtime_data, cpu);
	cea  = get_cpu_entry_area(cpu);

	/* Map #VC IST stack */
	vaddr = CEA_ESTACK_BOT(&cea->estacks, VC);
	pa    = __pa(data->ist_stack);
	cea_set_pte((void *)vaddr, pa, PAGE_KERNEL);

	/* Map VC fall-back stack */
	vaddr = CEA_ESTACK_BOT(&cea->estacks, VC2);
	pa    = __pa(data->fallback_stack);
	cea_set_pte((void *)vaddr, pa, PAGE_KERNEL);
}

static __always_inline bool on_vc_stack(struct pt_regs *regs)
{
	unsigned long sp = regs->sp;

	/* User-mode RSP is not trusted */
	if (user_mode(regs))
		return false;

	/* SYSCALL gap still has user-mode RSP */
	if (ip_within_syscall_gap(regs))
		return false;

	return ((sp >= __this_cpu_ist_bottom_va(VC)) && (sp < __this_cpu_ist_top_va(VC)));
}

/*
 * This function handles the case when an NMI is raised in the #VC
 * exception handler entry code, before the #VC handler has switched off
 * its IST stack. In this case, the IST entry for #VC must be adjusted,
 * so that any nested #VC exception will not overwrite the stack
 * contents of the interrupted #VC handler.
 *
 * The IST entry is adjusted unconditionally so that it can be also be
 * unconditionally adjusted back in __sev_es_ist_exit(). Otherwise a
 * nested sev_es_ist_exit() call may adjust back the IST entry too
 * early.
 *
 * The __sev_es_ist_enter() and __sev_es_ist_exit() functions always run
 * on the NMI IST stack, as they are only called from NMI handling code
 * right now.
 */
void noinstr __sev_es_ist_enter(struct pt_regs *regs)
{
	unsigned long old_ist, new_ist;

	/* Read old IST entry */
	new_ist = old_ist = __this_cpu_read(cpu_tss_rw.x86_tss.ist[IST_INDEX_VC]);

	/*
	 * If NMI happened while on the #VC IST stack, set the new IST
	 * value below regs->sp, so that the interrupted stack frame is
	 * not overwritten by subsequent #VC exceptions.
	 */
	if (on_vc_stack(regs))
		new_ist = regs->sp;

	/*
	 * Reserve additional 8 bytes and store old IST value so this
	 * adjustment can be unrolled in __sev_es_ist_exit().
	 */
	new_ist -= sizeof(old_ist);
	*(unsigned long *)new_ist = old_ist;

	/* Set new IST entry */
	this_cpu_write(cpu_tss_rw.x86_tss.ist[IST_INDEX_VC], new_ist);
}

void noinstr __sev_es_ist_exit(void)
{
	unsigned long ist;

	/* Read IST entry */
	ist = __this_cpu_read(cpu_tss_rw.x86_tss.ist[IST_INDEX_VC]);

	if (WARN_ON(ist == __this_cpu_ist_top_va(VC)))
		return;

	/* Read back old IST entry and write it to the TSS */
	this_cpu_write(cpu_tss_rw.x86_tss.ist[IST_INDEX_VC], *(unsigned long *)ist);
}

static void snp_register_ghcb(struct sev_es_runtime_data *data, unsigned long paddr)
{
	if (data->snp_ghcb_registered)
		return;

	snp_register_ghcb_early(paddr);

	data->snp_ghcb_registered = true;
}

static __always_inline struct ghcb *sev_es_get_ghcb(struct ghcb_state *state)
{
	struct sev_es_runtime_data *data;
	struct ghcb *ghcb;

	data = this_cpu_read(runtime_data);
	ghcb = &data->ghcb_page;

	if (unlikely(data->ghcb_active)) {
		/* GHCB is already in use - save its contents */

		if (unlikely(data->backup_ghcb_active))
			return NULL;

		/* Mark backup_ghcb active before writing to it */
		data->backup_ghcb_active = true;

		state->ghcb = &data->backup_ghcb;

		/* Backup GHCB content */
		*state->ghcb = *ghcb;
	} else {
		state->ghcb = NULL;
		data->ghcb_active = true;
	}

	/* SEV-SNP guest requires that GHCB must be registered. */
	if (sev_feature_enabled(SEV_SNP))
		snp_register_ghcb(data, __pa(ghcb));

	return ghcb;
}

static __always_inline void sev_es_put_ghcb(struct ghcb_state *state)
{
	struct sev_es_runtime_data *data;
	struct ghcb *ghcb;

	data = this_cpu_read(runtime_data);
	ghcb = &data->ghcb_page;

	if (state->ghcb) {
		/* Restore GHCB from Backup */
		*ghcb = *state->ghcb;
		data->backup_ghcb_active = false;
		state->ghcb = NULL;
	} else {
		data->ghcb_active = false;
	}
}

/* Needed in vc_early_forward_exception */
void do_early_exception(struct pt_regs *regs, int trapnr);

static inline u64 sev_es_rd_ghcb_msr(void)
{
	return __rdmsr(MSR_AMD64_SEV_ES_GHCB);
}

static __always_inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = (u32)(val);
	high = (u32)(val >> 32);

	native_wrmsr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

static int vc_fetch_insn_kernel(struct es_em_ctxt *ctxt,
				unsigned char *buffer)
{
	return copy_from_kernel_nofault(buffer, (unsigned char *)ctxt->regs->ip, MAX_INSN_SIZE);
}

static enum es_result __vc_decode_user_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	int res;

	res = insn_fetch_from_user_inatomic(ctxt->regs, buffer);
	if (!res) {
		ctxt->fi.vector     = X86_TRAP_PF;
		ctxt->fi.error_code = X86_PF_INSTR | X86_PF_USER;
		ctxt->fi.cr2        = ctxt->regs->ip;
		return ES_EXCEPTION;
	}

	if (!insn_decode_from_regs(&ctxt->insn, ctxt->regs, buffer, res))
		return ES_DECODE_FAILED;

	if (ctxt->insn.immediate.got)
		return ES_OK;
	else
		return ES_DECODE_FAILED;
}

static enum es_result __vc_decode_kern_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	int res, ret;

	res = vc_fetch_insn_kernel(ctxt, buffer);
	if (res) {
		ctxt->fi.vector     = X86_TRAP_PF;
		ctxt->fi.error_code = X86_PF_INSTR;
		ctxt->fi.cr2        = ctxt->regs->ip;
		return ES_EXCEPTION;
	}

	ret = insn_decode(&ctxt->insn, buffer, MAX_INSN_SIZE, INSN_MODE_64);
	if (ret < 0)
		return ES_DECODE_FAILED;
	else
		return ES_OK;
}

static enum es_result vc_decode_insn(struct es_em_ctxt *ctxt)
{
	if (user_mode(ctxt->regs))
		return __vc_decode_user_insn(ctxt);
	else
		return __vc_decode_kern_insn(ctxt);
}

static enum es_result vc_write_mem(struct es_em_ctxt *ctxt,
				   char *dst, char *buf, size_t size)
{
	unsigned long error_code = X86_PF_PROT | X86_PF_WRITE;
	char __user *target = (char __user *)dst;
	u64 d8;
	u32 d4;
	u16 d2;
	u8  d1;

	/* If instruction ran in kernel mode and the I/O buffer is in kernel space */
	if (!user_mode(ctxt->regs) && !access_ok(target, size)) {
		memcpy(dst, buf, size);
		return ES_OK;
	}

	switch (size) {
	case 1:
		memcpy(&d1, buf, 1);
		if (put_user(d1, target))
			goto fault;
		break;
	case 2:
		memcpy(&d2, buf, 2);
		if (put_user(d2, target))
			goto fault;
		break;
	case 4:
		memcpy(&d4, buf, 4);
		if (put_user(d4, target))
			goto fault;
		break;
	case 8:
		memcpy(&d8, buf, 8);
		if (put_user(d8, target))
			goto fault;
		break;
	default:
		WARN_ONCE(1, "%s: Invalid size: %zu\n", __func__, size);
		return ES_UNSUPPORTED;
	}

	return ES_OK;

fault:
	if (user_mode(ctxt->regs))
		error_code |= X86_PF_USER;

	ctxt->fi.vector = X86_TRAP_PF;
	ctxt->fi.error_code = error_code;
	ctxt->fi.cr2 = (unsigned long)dst;

	return ES_EXCEPTION;
}

static enum es_result vc_read_mem(struct es_em_ctxt *ctxt,
				  char *src, char *buf, size_t size)
{
	unsigned long error_code = X86_PF_PROT;
	char __user *s = (char __user *)src;
	u64 d8;
	u32 d4;
	u16 d2;
	u8  d1;

	/* If instruction ran in kernel mode and the I/O buffer is in kernel space */
	if (!user_mode(ctxt->regs) && !access_ok(s, size)) {
		memcpy(buf, src, size);
		return ES_OK;
	}

	switch (size) {
	case 1:
		if (get_user(d1, s))
			goto fault;
		memcpy(buf, &d1, 1);
		break;
	case 2:
		if (get_user(d2, s))
			goto fault;
		memcpy(buf, &d2, 2);
		break;
	case 4:
		if (get_user(d4, s))
			goto fault;
		memcpy(buf, &d4, 4);
		break;
	case 8:
		if (get_user(d8, s))
			goto fault;
		memcpy(buf, &d8, 8);
		break;
	default:
		WARN_ONCE(1, "%s: Invalid size: %zu\n", __func__, size);
		return ES_UNSUPPORTED;
	}

	return ES_OK;

fault:
	if (user_mode(ctxt->regs))
		error_code |= X86_PF_USER;

	ctxt->fi.vector = X86_TRAP_PF;
	ctxt->fi.error_code = error_code;
	ctxt->fi.cr2 = (unsigned long)src;

	return ES_EXCEPTION;
}

static enum es_result vc_slow_virt_to_phys(struct ghcb *ghcb, struct es_em_ctxt *ctxt,
					   unsigned long vaddr, phys_addr_t *paddr)
{
	unsigned long va = (unsigned long)vaddr;
	unsigned int level;
	phys_addr_t pa;
	pgd_t *pgd;
	pte_t *pte;

	pgd = __va(read_cr3_pa());
	pgd = &pgd[pgd_index(va)];
	pte = lookup_address_in_pgd(pgd, va, &level);
	if (!pte) {
		ctxt->fi.vector     = X86_TRAP_PF;
		ctxt->fi.cr2        = vaddr;
		ctxt->fi.error_code = 0;

		if (user_mode(ctxt->regs))
			ctxt->fi.error_code |= X86_PF_USER;

		return ES_EXCEPTION;
	}

	if (WARN_ON_ONCE(pte_val(*pte) & _PAGE_ENC))
		/* Emulated MMIO to/from encrypted memory not supported */
		return ES_UNSUPPORTED;

	pa = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
	pa |= va & ~page_level_mask(level);

	*paddr = pa;

	return ES_OK;
}

/* Include code shared with pre-decompression boot stage */
#include "sev-shared.c"

void noinstr __sev_es_nmi_complete(void)
{
	struct ghcb_state state;
	struct ghcb *ghcb;

	ghcb = sev_es_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_NMI_COMPLETE);
	ghcb_set_sw_exit_info_1(ghcb, 0);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	sev_es_wr_ghcb_msr(__pa_nodebug(ghcb));
	VMGEXIT();

	sev_es_put_ghcb(&state);
}

static u64 get_jump_table_addr(void)
{
	struct ghcb_state state;
	unsigned long flags;
	struct ghcb *ghcb;
	u64 ret = 0;

	local_irq_save(flags);

	ghcb = sev_es_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_JUMP_TABLE);
	ghcb_set_sw_exit_info_1(ghcb, SVM_VMGEXIT_GET_AP_JUMP_TABLE);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	if (ghcb_sw_exit_info_1_is_valid(ghcb) &&
	    ghcb_sw_exit_info_2_is_valid(ghcb))
		ret = ghcb->save.sw_exit_info_2;

	sev_es_put_ghcb(&state);

	local_irq_restore(flags);

	return ret;
}

static void pvalidate_pages(unsigned long vaddr, unsigned int npages, bool validate)
{
	unsigned long vaddr_end;
	int rc;

	vaddr = vaddr & PAGE_MASK;
	vaddr_end = vaddr + (npages << PAGE_SHIFT);

	while (vaddr < vaddr_end) {
		rc = pvalidate(vaddr, RMP_PG_SIZE_4K, validate);
		if (WARN(rc, "Failed to validate address 0x%lx ret %d", vaddr, rc))
			sev_es_terminate(1, GHCB_TERM_PVALIDATE);

		vaddr = vaddr + PAGE_SIZE;
	}
}

static void __init early_set_page_state(unsigned long paddr, unsigned int npages, int op)
{
	unsigned long paddr_end;
	u64 val;

	paddr = paddr & PAGE_MASK;
	paddr_end = paddr + (npages << PAGE_SHIFT);

	while (paddr < paddr_end) {
		/*
		 * Use the MSR protocol because this function can be called before the GHCB
		 * is established.
		 */
		sev_es_wr_ghcb_msr(GHCB_MSR_PSC_REQ_GFN(paddr >> PAGE_SHIFT, op));
		VMGEXIT();

		val = sev_es_rd_ghcb_msr();

		if (GHCB_RESP_CODE(val) != GHCB_MSR_PSC_RESP)
			goto e_term;

		if (WARN(GHCB_MSR_PSC_RESP_VAL(val),
			 "Failed to change page state to '%s' paddr 0x%lx error 0x%llx\n",
			 op == SNP_PAGE_STATE_PRIVATE ? "private" : "shared",
			 paddr, GHCB_MSR_PSC_RESP_VAL(val)))
			goto e_term;

		paddr = paddr + PAGE_SIZE;
	}

	return;

e_term:
	sev_es_terminate(1, GHCB_TERM_PSC);
}

void __init early_snp_set_memory_private(unsigned long vaddr, unsigned long paddr,
					 unsigned int npages)
{
	if (!sev_feature_enabled(SEV_SNP))
		return;

	 /* Ask hypervisor to add the memory pages in RMP table as a 'private'. */
	early_set_page_state(paddr, npages, SNP_PAGE_STATE_PRIVATE);

	/* Validate the memory pages after they've been added in the RMP table. */
	pvalidate_pages(vaddr, npages, 1);
}

void __init early_snp_set_memory_shared(unsigned long vaddr, unsigned long paddr,
					unsigned int npages)
{
	if (!sev_feature_enabled(SEV_SNP))
		return;

	/*
	 * Invalidate the memory pages before they are marked shared in the
	 * RMP table.
	 */
	pvalidate_pages(vaddr, npages, 0);

	 /* Ask hypervisor to make the memory pages shared in the RMP table. */
	early_set_page_state(paddr, npages, SNP_PAGE_STATE_SHARED);
}

void __init snp_prep_memory(unsigned long paddr, unsigned int sz, int op)
{
	unsigned long vaddr, npages;

	vaddr = (unsigned long)__va(paddr);
	npages = PAGE_ALIGN(sz) >> PAGE_SHIFT;

	switch (op) {
	case MEMORY_PRIVATE: {
		early_snp_set_memory_private(vaddr, paddr, npages);
		return;
	}
	case MEMORY_SHARED: {
		early_snp_set_memory_shared(vaddr, paddr, npages);
		return;
	}
	default:
		break;
	}

	WARN(1, "invalid memory op %d\n", op);
}

static int page_state_vmgexit(struct ghcb *ghcb, struct snp_page_state_change *data)
{
	struct snp_page_state_header *hdr;
	int ret = 0;

	hdr = &data->header;

	/*
	 * As per the GHCB specification, the hypervisor can resume the guest before
	 * processing all the entries. The loop checks whether all the entries are
	 * processed. If not, then keep retrying.
	 */
	while (hdr->cur_entry <= hdr->end_entry) {

		ghcb_set_sw_scratch(ghcb, (u64)__pa(data));

		ret = sev_es_ghcb_hv_call(ghcb, NULL, SVM_VMGEXIT_PSC, 0, 0);

		/* Page State Change VMGEXIT can pass error code through exit_info_2. */
		if (WARN(ret || ghcb->save.sw_exit_info_2,
			 "SEV-SNP: page state change failed ret=%d exit_info_2=%llx\n",
			 ret, ghcb->save.sw_exit_info_2))
			return 1;
	}

	return 0;
}

static void set_page_state(unsigned long vaddr, unsigned int npages, int op)
{
	struct snp_page_state_change *data;
	struct snp_page_state_header *hdr;
	struct snp_page_state_entry *e;
	unsigned long vaddr_end;
	struct ghcb_state state;
	struct ghcb *ghcb;
	int idx;

	vaddr = vaddr & PAGE_MASK;
	vaddr_end = vaddr + (npages << PAGE_SHIFT);

	ghcb = sev_es_get_ghcb(&state);
	if (unlikely(!ghcb))
		panic("SEV-SNP: Failed to get GHCB\n");

	data = (struct snp_page_state_change *)ghcb->shared_buffer;
	hdr = &data->header;

	while (vaddr < vaddr_end) {
		e = data->entry;
		memset(data, 0, sizeof(*data));

		for (idx = 0; idx < VMGEXIT_PSC_MAX_ENTRY; idx++, e++) {
			unsigned long pfn;

			if (is_vmalloc_addr((void *)vaddr))
				pfn = vmalloc_to_pfn((void *)vaddr);
			else
				pfn = __pa(vaddr) >> PAGE_SHIFT;

			e->gfn = pfn;
			e->operation = op;
			hdr->end_entry = idx;

			/*
			 * The GHCB specification provides the flexibility to
			 * use either 4K or 2MB page size in the RMP table.
			 * The current SNP support does not keep track of the
			 * page size used in the RMP table. To avoid the
			 * overlap request, use the 4K page size in the RMP
			 * table.
			 */
			e->pagesize = RMP_PG_SIZE_4K;
			vaddr = vaddr + PAGE_SIZE;

			if (vaddr >= vaddr_end)
				break;
		}

		/* Terminate the guest on page state change failure. */
		if (page_state_vmgexit(ghcb, data))
			sev_es_terminate(1, GHCB_TERM_PSC);
	}

	sev_es_put_ghcb(&state);
}

void snp_set_memory_shared(unsigned long vaddr, unsigned int npages)
{
	if (!sev_feature_enabled(SEV_SNP))
		return;

	pvalidate_pages(vaddr, npages, 0);

	set_page_state(vaddr, npages, SNP_PAGE_STATE_SHARED);
}

void snp_set_memory_private(unsigned long vaddr, unsigned int npages)
{
	if (!sev_feature_enabled(SEV_SNP))
		return;

	set_page_state(vaddr, npages, SNP_PAGE_STATE_PRIVATE);

	pvalidate_pages(vaddr, npages, 1);
}

static int snp_rmpadjust(void *va, unsigned int vmpl, unsigned int perm_mask, bool vmsa)
{
	unsigned int attrs;
	int err;

	attrs = (vmpl & RMPADJUST_VMPL_MASK) << RMPADJUST_VMPL_SHIFT;
	attrs |= (perm_mask & RMPADJUST_PERM_MASK_MASK) << RMPADJUST_PERM_MASK_SHIFT;
	if (vmsa)
		attrs |= RMPADJUST_VMSA_PAGE_BIT;

	/* Perform RMPADJUST */
	asm volatile (".byte 0xf3,0x0f,0x01,0xfe\n\t"
		      : "=a" (err)
		      : "a" (va), "c" (0), "d" (attrs)
		      : "memory", "cc");

	return err;
}

static int snp_clear_vmsa(void *vmsa)
{
	/*
	 * Clear the VMSA attribute for the page:
	 *   RDX[7:0]  = 1, Target VMPL level, must be numerically
	 *		    higher than current level (VMPL0)
	 *   RDX[15:8] = 0, Target permission mask (not used)
	 *   RDX[16]   = 0, Not a VMSA page
	 */
	return snp_rmpadjust(vmsa, RMPADJUST_VMPL_MAX, 0, false);
}

static int snp_set_vmsa(void *vmsa)
{
	/*
	 * To set the VMSA attribute for the page:
	 *   RDX[7:0]  = 1, Target VMPL level, must be numerically
	 *		    higher than current level (VMPL0)
	 *   RDX[15:8] = 0, Target permission mask (not used)
	 *   RDX[16]   = 1, VMSA page
	 */
	return snp_rmpadjust(vmsa, RMPADJUST_VMPL_MAX, 0, true);
}

#define INIT_CS_ATTRIBS		(SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK | SVM_SELECTOR_READ_MASK | SVM_SELECTOR_CODE_MASK)
#define INIT_DS_ATTRIBS		(SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK | SVM_SELECTOR_WRITE_MASK)

#define INIT_LDTR_ATTRIBS	(SVM_SELECTOR_P_MASK | 2)
#define INIT_TR_ATTRIBS		(SVM_SELECTOR_P_MASK | 3)

static int snp_wakeup_cpu_via_vmgexit(int apic_id, unsigned long start_ip)
{
	struct sev_es_save_area *cur_vmsa;
	struct sev_es_save_area *vmsa;
	struct ghcb_state state;
	struct ghcb *ghcb;
	unsigned long flags;
	u8 sipi_vector;
	u64 cr4;
	int cpu;
	int ret;

	if (!snp_ap_creation_supported())
		return -ENOTSUPP;

	/* Override start_ip with known SEV-ES/SEV-SNP starting RIP */
	if (start_ip == real_mode_header->trampoline_start) {
		start_ip = real_mode_header->sev_es_trampoline_start;
	} else {
		WARN_ONCE(1, "unsupported SEV-SNP start_ip: %lx\n", start_ip);
		return -EINVAL;
	}

	/* Find the logical CPU for the APIC ID */
	for_each_present_cpu(cpu) {
		if (arch_match_cpu_phys_id(cpu, apic_id))
			break;
	}
	if (cpu >= nr_cpu_ids)
		return -EINVAL;

	cur_vmsa = per_cpu(snp_vmsa, cpu);
	vmsa = (struct sev_es_save_area *)get_zeroed_page(GFP_KERNEL);
	if (!vmsa)
		return -ENOMEM;

	/* CR4 should maintain the MCE value */
	cr4 = native_read_cr4() & ~X86_CR4_MCE;

	/* Set the CS value based on the start_ip converted to a SIPI vector */
	sipi_vector = (start_ip >> 12);
	vmsa->cs.base     = sipi_vector << 12;
	vmsa->cs.limit    = 0xffff;
	vmsa->cs.attrib   = INIT_CS_ATTRIBS;
	vmsa->cs.selector = sipi_vector << 8;

	/* Set the RIP value based on start_ip */
	vmsa->rip = start_ip & 0xfff;

	/* Set VMSA entries to the INIT values as documented in the APM */
	vmsa->ds.limit    = 0xffff;
	vmsa->ds.attrib   = INIT_DS_ATTRIBS;
	vmsa->es = vmsa->ds;
	vmsa->fs = vmsa->ds;
	vmsa->gs = vmsa->ds;
	vmsa->ss = vmsa->ds;

	vmsa->gdtr.limit    = 0xffff;
	vmsa->ldtr.limit    = 0xffff;
	vmsa->ldtr.attrib   = INIT_LDTR_ATTRIBS;
	vmsa->idtr.limit    = 0xffff;
	vmsa->tr.limit      = 0xffff;
	vmsa->tr.attrib     = INIT_TR_ATTRIBS;

	vmsa->efer    = 0x1000;			/* Must set SVME bit */
	vmsa->cr4     = cr4;
	vmsa->cr0     = 0x60000010;
	vmsa->dr7     = 0x400;
	vmsa->dr6     = 0xffff0ff0;
	vmsa->rflags  = 0x2;
	vmsa->g_pat   = 0x0007040600070406ULL;
	vmsa->xcr0    = 0x1;
	vmsa->mxcsr   = 0x1f80;
	vmsa->x87_ftw = 0x5555;
	vmsa->x87_fcw = 0x0040;

	/*
	 * Set the SNP-specific fields for this VMSA:
	 *   VMPL level
	 *   SEV_FEATURES (matches the SEV STATUS MSR right shifted 2 bits)
	 */
	vmsa->vmpl = 0;
	vmsa->sev_features = sev_status >> 2;

	/* Switch the page over to a VMSA page now that it is initialized */
	ret = snp_set_vmsa(vmsa);
	if (ret) {
		pr_err("set VMSA page failed (%u)\n", ret);
		free_page((unsigned long)vmsa);

		return -EINVAL;
	}

	/* Issue VMGEXIT AP Creation NAE event */
	local_irq_save(flags);

	ghcb = sev_es_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	ghcb_set_rax(ghcb, vmsa->sev_features);
	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_CREATION);
	ghcb_set_sw_exit_info_1(ghcb, ((u64)apic_id << 32) | SVM_VMGEXIT_AP_CREATE);
	ghcb_set_sw_exit_info_2(ghcb, __pa(vmsa));

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	if (!ghcb_sw_exit_info_1_is_valid(ghcb) ||
	    lower_32_bits(ghcb->save.sw_exit_info_1)) {
		pr_alert("SNP AP Creation error\n");
		ret = -EINVAL;
	}

	sev_es_put_ghcb(&state);

	local_irq_restore(flags);

	/* Perform cleanup if there was an error */
	if (ret) {
		int err = snp_clear_vmsa(vmsa);

		if (err)
			pr_err("clear VMSA page failed (%u), leaking page\n", err);
		else
			free_page((unsigned long)vmsa);

		vmsa = NULL;
	}

	/* Free up any previous VMSA page */
	if (cur_vmsa) {
		int err = snp_clear_vmsa(cur_vmsa);

		if (err)
			pr_err("clear VMSA page failed (%u), leaking page\n", err);
		else
			free_page((unsigned long)cur_vmsa);
	}

	/* Record the current VMSA page */
	cur_vmsa = vmsa;

	return ret;
}

void snp_setup_wakeup_secondary_cpu(void)
{
	if (!sev_feature_enabled(SEV_SNP))
		return;

	apic->wakeup_secondary_cpu = snp_wakeup_cpu_via_vmgexit;
}

int sev_es_setup_ap_jump_table(struct real_mode_header *rmh)
{
	u16 startup_cs, startup_ip;
	phys_addr_t jump_table_pa;
	u64 jump_table_addr;
	u16 __iomem *jump_table;

	jump_table_addr = get_jump_table_addr();

	/* On UP guests there is no jump table so this is not a failure */
	if (!jump_table_addr)
		return 0;

	/* Check if AP Jump Table is page-aligned */
	if (jump_table_addr & ~PAGE_MASK)
		return -EINVAL;

	jump_table_pa = jump_table_addr & PAGE_MASK;

	startup_cs = (u16)(rmh->trampoline_start >> 4);
	startup_ip = (u16)(rmh->sev_es_trampoline_start -
			   rmh->trampoline_start);

	jump_table = ioremap_encrypted(jump_table_pa, PAGE_SIZE);
	if (!jump_table)
		return -EIO;

	writew(startup_ip, &jump_table[0]);
	writew(startup_cs, &jump_table[1]);

	iounmap(jump_table);

	return 0;
}

/*
 * This is needed by the OVMF UEFI firmware which will use whatever it finds in
 * the GHCB MSR as its GHCB to talk to the hypervisor. So make sure the per-cpu
 * runtime GHCBs used by the kernel are also mapped in the EFI page-table.
 */
int __init sev_es_efi_map_ghcbs(pgd_t *pgd)
{
	struct sev_es_runtime_data *data;
	unsigned long address, pflags;
	int cpu;
	u64 pfn;

	if (!sev_es_active())
		return 0;

	pflags = _PAGE_NX | _PAGE_RW;

	for_each_possible_cpu(cpu) {
		data = per_cpu(runtime_data, cpu);

		address = __pa(&data->ghcb_page);
		pfn = address >> PAGE_SHIFT;

		if (kernel_map_pages_in_pgd(pgd, pfn, address, 1, pflags))
			return 1;
	}

	return 0;
}

static enum es_result vc_handle_msr(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	struct pt_regs *regs = ctxt->regs;
	enum es_result ret;
	u64 exit_info_1;

	/* Is it a WRMSR? */
	exit_info_1 = (ctxt->insn.opcode.bytes[1] == 0x30) ? 1 : 0;

	ghcb_set_rcx(ghcb, regs->cx);
	if (exit_info_1) {
		ghcb_set_rax(ghcb, regs->ax);
		ghcb_set_rdx(ghcb, regs->dx);
	}

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_MSR, exit_info_1, 0);

	if ((ret == ES_OK) && (!exit_info_1)) {
		regs->ax = ghcb->save.rax;
		regs->dx = ghcb->save.rdx;
	}

	return ret;
}

/*
 * This function runs on the first #VC exception after the kernel
 * switched to virtual addresses.
 */
static bool __init sev_es_setup_ghcb(void)
{
	/* First make sure the hypervisor talks a supported protocol. */
	if (!sev_es_negotiate_protocol())
		return false;

	/* If SNP is active, make sure that hypervisor supports the feature. */
	if (sev_feature_enabled(SEV_SNP) && !sev_snp_check_hypervisor_features())
		sev_es_terminate(0, GHCB_SEV_ES_SNP_UNSUPPORTED);

	/*
	 * Clear the boot_ghcb. The first exception comes in before the bss
	 * section is cleared.
	 */
	memset(&boot_ghcb_page, 0, PAGE_SIZE);

	/* Alright - Make the boot-ghcb public */
	boot_ghcb = &boot_ghcb_page;

	/* SEV-SNP guest requires that GHCB GPA must be registered. */
	if (sev_feature_enabled(SEV_SNP))
		snp_register_ghcb_early(__pa(&boot_ghcb_page));

	return true;
}

#ifdef CONFIG_HOTPLUG_CPU
static void sev_es_ap_hlt_loop(void)
{
	struct ghcb_state state;
	struct ghcb *ghcb;

	ghcb = sev_es_get_ghcb(&state);

	while (true) {
		vc_ghcb_invalidate(ghcb);
		ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_HLT_LOOP);
		ghcb_set_sw_exit_info_1(ghcb, 0);
		ghcb_set_sw_exit_info_2(ghcb, 0);

		sev_es_wr_ghcb_msr(__pa(ghcb));
		VMGEXIT();

		/* Wakeup signal? */
		if (ghcb_sw_exit_info_2_is_valid(ghcb) &&
		    ghcb->save.sw_exit_info_2)
			break;
	}

	sev_es_put_ghcb(&state);
}

/*
 * Play_dead handler when running under SEV-ES. This is needed because
 * the hypervisor can't deliver an SIPI request to restart the AP.
 * Instead the kernel has to issue a VMGEXIT to halt the VCPU until the
 * hypervisor wakes it up again.
 */
static void sev_es_play_dead(void)
{
	play_dead_common();

	/* IRQs now disabled */

	sev_es_ap_hlt_loop();

	/*
	 * If we get here, the VCPU was woken up again. Jump to CPU
	 * startup code to get it back online.
	 */
	start_cpu0();
}
#else  /* CONFIG_HOTPLUG_CPU */
#define sev_es_play_dead	native_play_dead
#endif /* CONFIG_HOTPLUG_CPU */

#ifdef CONFIG_SMP
static void __init sev_es_setup_play_dead(void)
{
	smp_ops.play_dead = sev_es_play_dead;
}
#else
static inline void sev_es_setup_play_dead(void) { }
#endif

static void __init alloc_runtime_data(int cpu)
{
	struct sev_es_runtime_data *data;

	data = memblock_alloc(sizeof(*data), PAGE_SIZE);
	if (!data)
		panic("Can't allocate SEV-ES runtime data");

	per_cpu(runtime_data, cpu) = data;
}

static void __init init_ghcb(int cpu)
{
	struct sev_es_runtime_data *data;
	int err;

	data = per_cpu(runtime_data, cpu);

	err = early_set_memory_decrypted((unsigned long)&data->ghcb_page,
					 sizeof(data->ghcb_page));
	if (err)
		panic("Can't map GHCBs unencrypted");

	memset(&data->ghcb_page, 0, sizeof(data->ghcb_page));

	data->ghcb_active = false;
	data->backup_ghcb_active = false;
	data->snp_ghcb_registered = false;
}

void __init sev_es_init_vc_handling(void)
{
	int cpu;

	BUILD_BUG_ON(offsetof(struct sev_es_runtime_data, ghcb_page) % PAGE_SIZE);

	if (!sev_es_active())
		return;

	if (!sev_es_check_cpu_features())
		panic("SEV-ES CPU Features missing");

	/* Enable SEV-ES special handling */
	static_branch_enable(&sev_es_enable_key);

	/* Initialize per-cpu GHCB pages */
	for_each_possible_cpu(cpu) {
		alloc_runtime_data(cpu);
		init_ghcb(cpu);
		setup_vc_stacks(cpu);
	}

	sev_es_setup_play_dead();

	/* Secondary CPUs use the runtime #VC handler */
	initial_vc_handler = (unsigned long)safe_stack_exc_vmm_communication;
}

static void __init vc_early_forward_exception(struct es_em_ctxt *ctxt)
{
	int trapnr = ctxt->fi.vector;

	if (trapnr == X86_TRAP_PF)
		native_write_cr2(ctxt->fi.cr2);

	ctxt->regs->orig_ax = ctxt->fi.error_code;
	do_early_exception(ctxt->regs, trapnr);
}

static long *vc_insn_get_reg(struct es_em_ctxt *ctxt)
{
	long *reg_array;
	int offset;

	reg_array = (long *)ctxt->regs;
	offset    = insn_get_modrm_reg_off(&ctxt->insn, ctxt->regs);

	if (offset < 0)
		return NULL;

	offset /= sizeof(long);

	return reg_array + offset;
}

static long *vc_insn_get_rm(struct es_em_ctxt *ctxt)
{
	long *reg_array;
	int offset;

	reg_array = (long *)ctxt->regs;
	offset    = insn_get_modrm_rm_off(&ctxt->insn, ctxt->regs);

	if (offset < 0)
		return NULL;

	offset /= sizeof(long);

	return reg_array + offset;
}
static enum es_result vc_do_mmio(struct ghcb *ghcb, struct es_em_ctxt *ctxt,
				 unsigned int bytes, bool read)
{
	u64 exit_code, exit_info_1, exit_info_2;
	unsigned long ghcb_pa = __pa(ghcb);
	enum es_result res;
	phys_addr_t paddr;
	void __user *ref;

	ref = insn_get_addr_ref(&ctxt->insn, ctxt->regs);
	if (ref == (void __user *)-1L)
		return ES_UNSUPPORTED;

	exit_code = read ? SVM_VMGEXIT_MMIO_READ : SVM_VMGEXIT_MMIO_WRITE;

	res = vc_slow_virt_to_phys(ghcb, ctxt, (unsigned long)ref, &paddr);
	if (res != ES_OK) {
		if (res == ES_EXCEPTION && !read)
			ctxt->fi.error_code |= X86_PF_WRITE;

		return res;
	}

	exit_info_1 = paddr;
	/* Can never be greater than 8 */
	exit_info_2 = bytes;

	ghcb_set_sw_scratch(ghcb, ghcb_pa + offsetof(struct ghcb, shared_buffer));

	return sev_es_ghcb_hv_call(ghcb, ctxt, exit_code, exit_info_1, exit_info_2);
}

static enum es_result vc_handle_mmio_twobyte_ops(struct ghcb *ghcb,
						 struct es_em_ctxt *ctxt)
{
	struct insn *insn = &ctxt->insn;
	unsigned int bytes = 0;
	enum es_result ret;
	int sign_byte;
	long *reg_data;

	switch (insn->opcode.bytes[1]) {
		/* MMIO Read w/ zero-extension */
	case 0xb6:
		bytes = 1;
		fallthrough;
	case 0xb7:
		if (!bytes)
			bytes = 2;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		/* Zero extend based on operand size */
		reg_data = vc_insn_get_reg(ctxt);
		if (!reg_data)
			return ES_DECODE_FAILED;

		memset(reg_data, 0, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

		/* MMIO Read w/ sign-extension */
	case 0xbe:
		bytes = 1;
		fallthrough;
	case 0xbf:
		if (!bytes)
			bytes = 2;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		/* Sign extend based on operand size */
		reg_data = vc_insn_get_reg(ctxt);
		if (!reg_data)
			return ES_DECODE_FAILED;

		if (bytes == 1) {
			u8 *val = (u8 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x80) ? 0xff : 0x00;
		} else {
			u16 *val = (u16 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x8000) ? 0xff : 0x00;
		}
		memset(reg_data, sign_byte, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

	default:
		ret = ES_UNSUPPORTED;
	}

	return ret;
}

/*
 * The MOVS instruction has two memory operands, which raises the
 * problem that it is not known whether the access to the source or the
 * destination caused the #VC exception (and hence whether an MMIO read
 * or write operation needs to be emulated).
 *
 * Instead of playing games with walking page-tables and trying to guess
 * whether the source or destination is an MMIO range, split the move
 * into two operations, a read and a write with only one memory operand.
 * This will cause a nested #VC exception on the MMIO address which can
 * then be handled.
 *
 * This implementation has the benefit that it also supports MOVS where
 * source _and_ destination are MMIO regions.
 *
 * It will slow MOVS on MMIO down a lot, but in SEV-ES guests it is a
 * rare operation. If it turns out to be a performance problem the split
 * operations can be moved to memcpy_fromio() and memcpy_toio().
 */
static enum es_result vc_handle_mmio_movs(struct es_em_ctxt *ctxt,
					  unsigned int bytes)
{
	unsigned long ds_base, es_base;
	unsigned char *src, *dst;
	unsigned char buffer[8];
	enum es_result ret;
	bool rep;
	int off;

	ds_base = insn_get_seg_base(ctxt->regs, INAT_SEG_REG_DS);
	es_base = insn_get_seg_base(ctxt->regs, INAT_SEG_REG_ES);

	if (ds_base == -1L || es_base == -1L) {
		ctxt->fi.vector = X86_TRAP_GP;
		ctxt->fi.error_code = 0;
		return ES_EXCEPTION;
	}

	src = ds_base + (unsigned char *)ctxt->regs->si;
	dst = es_base + (unsigned char *)ctxt->regs->di;

	ret = vc_read_mem(ctxt, src, buffer, bytes);
	if (ret != ES_OK)
		return ret;

	ret = vc_write_mem(ctxt, dst, buffer, bytes);
	if (ret != ES_OK)
		return ret;

	if (ctxt->regs->flags & X86_EFLAGS_DF)
		off = -bytes;
	else
		off =  bytes;

	ctxt->regs->si += off;
	ctxt->regs->di += off;

	rep = insn_has_rep_prefix(&ctxt->insn);
	if (rep)
		ctxt->regs->cx -= 1;

	if (!rep || ctxt->regs->cx == 0)
		return ES_OK;
	else
		return ES_RETRY;
}

static enum es_result vc_handle_mmio(struct ghcb *ghcb,
				     struct es_em_ctxt *ctxt)
{
	struct insn *insn = &ctxt->insn;
	unsigned int bytes = 0;
	enum es_result ret;
	long *reg_data;

	switch (insn->opcode.bytes[0]) {
	/* MMIO Write */
	case 0x88:
		bytes = 1;
		fallthrough;
	case 0x89:
		if (!bytes)
			bytes = insn->opnd_bytes;

		reg_data = vc_insn_get_reg(ctxt);
		if (!reg_data)
			return ES_DECODE_FAILED;

		memcpy(ghcb->shared_buffer, reg_data, bytes);

		ret = vc_do_mmio(ghcb, ctxt, bytes, false);
		break;

	case 0xc6:
		bytes = 1;
		fallthrough;
	case 0xc7:
		if (!bytes)
			bytes = insn->opnd_bytes;

		memcpy(ghcb->shared_buffer, insn->immediate1.bytes, bytes);

		ret = vc_do_mmio(ghcb, ctxt, bytes, false);
		break;

		/* MMIO Read */
	case 0x8a:
		bytes = 1;
		fallthrough;
	case 0x8b:
		if (!bytes)
			bytes = insn->opnd_bytes;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		reg_data = vc_insn_get_reg(ctxt);
		if (!reg_data)
			return ES_DECODE_FAILED;

		/* Zero-extend for 32-bit operation */
		if (bytes == 4)
			*reg_data = 0;

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

		/* MOVS instruction */
	case 0xa4:
		bytes = 1;
		fallthrough;
	case 0xa5:
		if (!bytes)
			bytes = insn->opnd_bytes;

		ret = vc_handle_mmio_movs(ctxt, bytes);
		break;
		/* Two-Byte Opcodes */
	case 0x0f:
		ret = vc_handle_mmio_twobyte_ops(ghcb, ctxt);
		break;
	default:
		ret = ES_UNSUPPORTED;
	}

	return ret;
}

static enum es_result vc_handle_dr7_write(struct ghcb *ghcb,
					  struct es_em_ctxt *ctxt)
{
	struct sev_es_runtime_data *data = this_cpu_read(runtime_data);
	long val, *reg = vc_insn_get_rm(ctxt);
	enum es_result ret;

	if (!reg)
		return ES_DECODE_FAILED;

	val = *reg;

	/* Upper 32 bits must be written as zeroes */
	if (val >> 32) {
		ctxt->fi.vector = X86_TRAP_GP;
		ctxt->fi.error_code = 0;
		return ES_EXCEPTION;
	}

	/* Clear out other reserved bits and set bit 10 */
	val = (val & 0xffff23ffL) | BIT(10);

	/* Early non-zero writes to DR7 are not supported */
	if (!data && (val & ~DR7_RESET_VALUE))
		return ES_UNSUPPORTED;

	/* Using a value of 0 for ExitInfo1 means RAX holds the value */
	ghcb_set_rax(ghcb, val);
	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_WRITE_DR7, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (data)
		data->dr7 = val;

	return ES_OK;
}

static enum es_result vc_handle_dr7_read(struct ghcb *ghcb,
					 struct es_em_ctxt *ctxt)
{
	struct sev_es_runtime_data *data = this_cpu_read(runtime_data);
	long *reg = vc_insn_get_rm(ctxt);

	if (!reg)
		return ES_DECODE_FAILED;

	if (data)
		*reg = data->dr7;
	else
		*reg = DR7_RESET_VALUE;

	return ES_OK;
}

static enum es_result vc_handle_wbinvd(struct ghcb *ghcb,
				       struct es_em_ctxt *ctxt)
{
	return sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_WBINVD, 0, 0);
}

static enum es_result vc_handle_rdpmc(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	enum es_result ret;

	ghcb_set_rcx(ghcb, ctxt->regs->cx);

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_RDPMC, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!(ghcb_rax_is_valid(ghcb) && ghcb_rdx_is_valid(ghcb)))
		return ES_VMM_ERROR;

	ctxt->regs->ax = ghcb->save.rax;
	ctxt->regs->dx = ghcb->save.rdx;

	return ES_OK;
}

static enum es_result vc_handle_monitor(struct ghcb *ghcb,
					struct es_em_ctxt *ctxt)
{
	/*
	 * Treat it as a NOP and do not leak a physical address to the
	 * hypervisor.
	 */
	return ES_OK;
}

static enum es_result vc_handle_mwait(struct ghcb *ghcb,
				      struct es_em_ctxt *ctxt)
{
	/* Treat the same as MONITOR/MONITORX */
	return ES_OK;
}

static enum es_result vc_handle_vmmcall(struct ghcb *ghcb,
					struct es_em_ctxt *ctxt)
{
	enum es_result ret;

	ghcb_set_rax(ghcb, ctxt->regs->ax);
	ghcb_set_cpl(ghcb, user_mode(ctxt->regs) ? 3 : 0);

	if (x86_platform.hyper.sev_es_hcall_prepare)
		x86_platform.hyper.sev_es_hcall_prepare(ghcb, ctxt->regs);

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_VMMCALL, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!ghcb_rax_is_valid(ghcb))
		return ES_VMM_ERROR;

	ctxt->regs->ax = ghcb->save.rax;

	/*
	 * Call sev_es_hcall_finish() after regs->ax is already set.
	 * This allows the hypervisor handler to overwrite it again if
	 * necessary.
	 */
	if (x86_platform.hyper.sev_es_hcall_finish &&
	    !x86_platform.hyper.sev_es_hcall_finish(ghcb, ctxt->regs))
		return ES_VMM_ERROR;

	return ES_OK;
}

static enum es_result vc_handle_trap_ac(struct ghcb *ghcb,
					struct es_em_ctxt *ctxt)
{
	/*
	 * Calling ecx_alignment_check() directly does not work, because it
	 * enables IRQs and the GHCB is active. Forward the exception and call
	 * it later from vc_forward_exception().
	 */
	ctxt->fi.vector = X86_TRAP_AC;
	ctxt->fi.error_code = 0;
	return ES_EXCEPTION;
}

static __always_inline void vc_handle_trap_db(struct pt_regs *regs)
{
	if (user_mode(regs))
		noist_exc_debug(regs);
	else
		exc_debug(regs);
}

static enum es_result vc_handle_exitcode(struct es_em_ctxt *ctxt,
					 struct ghcb *ghcb,
					 unsigned long exit_code)
{
	enum es_result result;

	switch (exit_code) {
	case SVM_EXIT_READ_DR7:
		result = vc_handle_dr7_read(ghcb, ctxt);
		break;
	case SVM_EXIT_WRITE_DR7:
		result = vc_handle_dr7_write(ghcb, ctxt);
		break;
	case SVM_EXIT_EXCP_BASE + X86_TRAP_AC:
		result = vc_handle_trap_ac(ghcb, ctxt);
		break;
	case SVM_EXIT_RDTSC:
	case SVM_EXIT_RDTSCP:
		result = vc_handle_rdtsc(ghcb, ctxt, exit_code);
		break;
	case SVM_EXIT_RDPMC:
		result = vc_handle_rdpmc(ghcb, ctxt);
		break;
	case SVM_EXIT_INVD:
		pr_err_ratelimited("#VC exception for INVD??? Seriously???\n");
		result = ES_UNSUPPORTED;
		break;
	case SVM_EXIT_CPUID:
		result = vc_handle_cpuid(ghcb, ctxt);
		break;
	case SVM_EXIT_IOIO:
		result = vc_handle_ioio(ghcb, ctxt);
		break;
	case SVM_EXIT_MSR:
		result = vc_handle_msr(ghcb, ctxt);
		break;
	case SVM_EXIT_VMMCALL:
		result = vc_handle_vmmcall(ghcb, ctxt);
		break;
	case SVM_EXIT_WBINVD:
		result = vc_handle_wbinvd(ghcb, ctxt);
		break;
	case SVM_EXIT_MONITOR:
		result = vc_handle_monitor(ghcb, ctxt);
		break;
	case SVM_EXIT_MWAIT:
		result = vc_handle_mwait(ghcb, ctxt);
		break;
	case SVM_EXIT_NPF:
		result = vc_handle_mmio(ghcb, ctxt);
		break;
	default:
		/*
		 * Unexpected #VC exception
		 */
		result = ES_UNSUPPORTED;
	}

	return result;
}

static __always_inline void vc_forward_exception(struct es_em_ctxt *ctxt)
{
	long error_code = ctxt->fi.error_code;
	int trapnr = ctxt->fi.vector;

	ctxt->regs->orig_ax = ctxt->fi.error_code;

	switch (trapnr) {
	case X86_TRAP_GP:
		exc_general_protection(ctxt->regs, error_code);
		break;
	case X86_TRAP_UD:
		exc_invalid_op(ctxt->regs);
		break;
	case X86_TRAP_AC:
		exc_alignment_check(ctxt->regs, error_code);
		break;
	default:
		pr_emerg("Unsupported exception in #VC instruction emulation - can't continue\n");
		BUG();
	}
}

static __always_inline bool on_vc_fallback_stack(struct pt_regs *regs)
{
	unsigned long sp = (unsigned long)regs;

	return (sp >= __this_cpu_ist_bottom_va(VC2) && sp < __this_cpu_ist_top_va(VC2));
}

/*
 * Main #VC exception handler. It is called when the entry code was able to
 * switch off the IST to a safe kernel stack.
 *
 * With the current implementation it is always possible to switch to a safe
 * stack because #VC exceptions only happen at known places, like intercepted
 * instructions or accesses to MMIO areas/IO ports. They can also happen with
 * code instrumentation when the hypervisor intercepts #DB, but the critical
 * paths are forbidden to be instrumented, so #DB exceptions currently also
 * only happen in safe places.
 */
DEFINE_IDTENTRY_VC_SAFE_STACK(exc_vmm_communication)
{
	struct sev_es_runtime_data *data = this_cpu_read(runtime_data);
	irqentry_state_t irq_state;
	struct ghcb_state state;
	struct es_em_ctxt ctxt;
	enum es_result result;
	struct ghcb *ghcb;

	/*
	 * Handle #DB before calling into !noinstr code to avoid recursive #DB.
	 */
	if (error_code == SVM_EXIT_EXCP_BASE + X86_TRAP_DB) {
		vc_handle_trap_db(regs);
		return;
	}

	irq_state = irqentry_nmi_enter(regs);
	lockdep_assert_irqs_disabled();
	instrumentation_begin();

	/*
	 * This is invoked through an interrupt gate, so IRQs are disabled. The
	 * code below might walk page-tables for user or kernel addresses, so
	 * keep the IRQs disabled to protect us against concurrent TLB flushes.
	 */

	ghcb = sev_es_get_ghcb(&state);
	if (!ghcb) {
		/*
		 * Mark GHCBs inactive so that panic() is able to print the
		 * message.
		 */
		data->ghcb_active        = false;
		data->backup_ghcb_active = false;

		panic("Unable to handle #VC exception! GHCB and Backup GHCB are already in use");
	}

	vc_ghcb_invalidate(ghcb);
	result = vc_init_em_ctxt(&ctxt, regs, error_code);

	if (result == ES_OK)
		result = vc_handle_exitcode(&ctxt, ghcb, error_code);

	sev_es_put_ghcb(&state);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		vc_finish_insn(&ctxt);
		break;
	case ES_UNSUPPORTED:
		pr_err_ratelimited("Unsupported exit-code 0x%02lx in early #VC exception (IP: 0x%lx)\n",
				   error_code, regs->ip);
		goto fail;
	case ES_VMM_ERROR:
		pr_err_ratelimited("Failure in communication with VMM (exit-code 0x%02lx IP: 0x%lx)\n",
				   error_code, regs->ip);
		goto fail;
	case ES_DECODE_FAILED:
		pr_err_ratelimited("Failed to decode instruction (exit-code 0x%02lx IP: 0x%lx)\n",
				   error_code, regs->ip);
		goto fail;
	case ES_EXCEPTION:
		vc_forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		pr_emerg("Unknown result in %s():%d\n", __func__, result);
		/*
		 * Emulating the instruction which caused the #VC exception
		 * failed - can't continue so print debug information
		 */
		BUG();
	}

out:
	instrumentation_end();
	irqentry_nmi_exit(regs, irq_state);

	return;

fail:
	if (user_mode(regs)) {
		/*
		 * Do not kill the machine if user-space triggered the
		 * exception. Send SIGBUS instead and let user-space deal with
		 * it.
		 */
		force_sig_fault(SIGBUS, BUS_OBJERR, (void __user *)0);
	} else {
		pr_emerg("PANIC: Unhandled #VC exception in kernel space (result=%d)\n",
			 result);

		/* Show some debug info */
		show_regs(regs);

		/* Ask hypervisor to sev_es_terminate */
		sev_es_terminate(0, GHCB_SEV_ES_GEN_REQ);

		/* If that fails and we get here - just panic */
		panic("Returned from Terminate-Request to Hypervisor\n");
	}

	goto out;
}

/* This handler runs on the #VC fall-back stack. It can cause further #VC exceptions */
DEFINE_IDTENTRY_VC_IST(exc_vmm_communication)
{
	instrumentation_begin();
	panic("Can't handle #VC exception from unsupported context\n");
	instrumentation_end();
}

DEFINE_IDTENTRY_VC(exc_vmm_communication)
{
	if (likely(!on_vc_fallback_stack(regs)))
		safe_stack_exc_vmm_communication(regs, error_code);
	else
		ist_exc_vmm_communication(regs, error_code);
}

bool __init handle_vc_boot_ghcb(struct pt_regs *regs)
{
	unsigned long exit_code = regs->orig_ax;
	struct es_em_ctxt ctxt;
	enum es_result result;

	/* Do initial setup or terminate the guest */
	if (unlikely(boot_ghcb == NULL && !sev_es_setup_ghcb()))
		sev_es_terminate(0, GHCB_SEV_ES_GEN_REQ);

	vc_ghcb_invalidate(boot_ghcb);

	result = vc_init_em_ctxt(&ctxt, regs, exit_code);
	if (result == ES_OK)
		result = vc_handle_exitcode(&ctxt, boot_ghcb, exit_code);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		vc_finish_insn(&ctxt);
		break;
	case ES_UNSUPPORTED:
		early_printk("PANIC: Unsupported exit-code 0x%02lx in early #VC exception (IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_VMM_ERROR:
		early_printk("PANIC: Failure in communication with VMM (exit-code 0x%02lx IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_DECODE_FAILED:
		early_printk("PANIC: Failed to decode instruction (exit-code 0x%02lx IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_EXCEPTION:
		vc_early_forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		BUG();
	}

	return true;

fail:
	show_regs(regs);

	while (true)
		halt();
}

static struct resource guest_req_res[0];
static struct platform_device guest_req_device = {
	.name		= "snp-guest",
	.id		= -1,
	.resource	= guest_req_res,
	.num_resources	= 1,
};

static struct snp_secrets_page_layout *snp_map_secrets_page(void)
{
	u16 __iomem *secrets;

	if (!snp_secrets_phys || !sev_feature_enabled(SEV_SNP))
		return NULL;

	secrets = ioremap_encrypted(snp_secrets_phys, PAGE_SIZE);
	if (!secrets)
		return NULL;

	return (struct snp_secrets_page_layout *)secrets;
}

u64 snp_msg_seqno(void)
{
	struct snp_secrets_page_layout *layout;
	u64 count;

	layout = snp_map_secrets_page();
	if (layout == NULL)
		return 0;

	/* Read the current message sequence counter from secrets pages */
	count = readl(&layout->os_area.msg_seqno_0);

	iounmap(layout);

	/*
	 * The message sequence counter for the SNP guest request is a 64-bit value
	 * but the version 2 of GHCB specification defines the 32-bit storage for the
	 * it.
	 */
	if ((count + 1) >= INT_MAX)
		return 0;

	return count + 1;
}
EXPORT_SYMBOL_GPL(snp_msg_seqno);

static void snp_gen_msg_seqno(void)
{
	struct snp_secrets_page_layout *layout;
	u64 count;

	layout = snp_map_secrets_page();
	if (layout == NULL)
		return;

	/* Increment the sequence counter by 2 and save in secrets page. */
	count = readl(&layout->os_area.msg_seqno_0);
	count += 2;

	writel(count, &layout->os_area.msg_seqno_0);
	iounmap(layout);
}

static int get_snp_secrets_resource(struct resource *res)
{
	struct setup_header *hdr = &boot_params.hdr;
	struct cc_blob_sev_info *info;
	unsigned long paddr;
	int ret = -ENODEV;

	/*
	 * The secret page contains the VM encryption key used for encrypting the
	 * messages between the guest and the PSP. The secrets page location is
	 * available either through the setup_data or EFI configuration table.
	 */
	if (hdr->cc_blob_address) {
		paddr = hdr->cc_blob_address;
	} else if (efi_enabled(EFI_CONFIG_TABLES)) {
#ifdef CONFIG_EFI
		paddr = cc_blob_phys;
#else
		return -ENODEV;
#endif
	} else {
		return -ENODEV;
	}

	info = memremap(paddr, sizeof(*info), MEMREMAP_WB);
	if (!info)
		return -ENOMEM;

	/* Verify the header that its a valid SEV_SNP CC header */
	if ((info->magic == CC_BLOB_SEV_HDR_MAGIC) &&
	    info->secrets_phys &&
	    (info->secrets_len == PAGE_SIZE)) {
		res->start = info->secrets_phys;
		res->end = info->secrets_phys + info->secrets_len;
		res->flags = IORESOURCE_MEM;
		snp_secrets_phys = info->secrets_phys;
		ret = 0;
	}

	memunmap(info);
	return ret;
}

static int __init add_snp_guest_request(void)
{
	if (!sev_feature_enabled(SEV_SNP))
		return -ENODEV;

	if (get_snp_secrets_resource(&guest_req_res[0]))
		return -ENODEV;

	platform_device_register(&guest_req_device);
	dev_info(&guest_req_device.dev, "registered [secret 0x%llx - 0x%llx]\n",
		guest_req_res[0].start, guest_req_res[0].end);

	return 0;
}
device_initcall(add_snp_guest_request);

unsigned long snp_issue_guest_request(int type, struct snp_guest_request_data *input)
{
	struct ghcb_state state;
	struct ghcb *ghcb;
	unsigned long id;
	int ret;

	if (!sev_feature_enabled(SEV_SNP))
		return -ENODEV;

	if (type == GUEST_REQUEST)
		id = SVM_VMGEXIT_GUEST_REQUEST;
	else
		return -EINVAL;

	ghcb = sev_es_get_ghcb(&state);
	if (!ghcb)
		return -ENODEV;

	vc_ghcb_invalidate(ghcb);
	ghcb_set_rax(ghcb, input->data_gpa);
	ghcb_set_rbx(ghcb, input->data_npages);

	ret = sev_es_ghcb_hv_call(ghcb, NULL, id, input->req_gpa, input->resp_gpa);
	if (ret)
		goto e_put;

	if (ghcb->save.sw_exit_info_2) {
		ret = ghcb->save.sw_exit_info_2;
		goto e_put;
	}

	/* Command was successful, increment the message sequence counter. */
	snp_gen_msg_seqno();

e_put:
	sev_es_put_ghcb(&state);
	return ret;
}
EXPORT_SYMBOL_GPL(snp_issue_guest_request);

#undef pr_fmt
#define pr_fmt(fmt)	"SEV-SNP: " fmt

static int __snp_enable(unsigned int cpu)
{
	u64 val;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return 0;

	rdmsrl(MSR_AMD64_SYSCFG, val);

	val |= MSR_AMD64_SYSCFG_SNP_EN;
	val |= MSR_AMD64_SYSCFG_SNP_VMPL_EN;

	wrmsrl(MSR_AMD64_SYSCFG, val);

	return 0;
}

static __init void snp_enable(void *arg)
{
	__snp_enable(smp_processor_id());
}

static __init int __snp_rmptable_init(void)
{
	u64 rmp_base, rmp_end;
	unsigned long sz;
	void *start;
	u64 val;

	rdmsrl(MSR_AMD64_RMP_BASE, rmp_base);
	rdmsrl(MSR_AMD64_RMP_END, rmp_end);

	if (!rmp_base || !rmp_end) {
		pr_info("Memory for the RMP table has not been reserved by BIOS\n");
		return 1;
	}

	sz = rmp_end - rmp_base + 1;

	start = memremap(rmp_base, sz, MEMREMAP_WB);
	if (!start) {
		pr_err("Failed to map RMP table 0x%llx-0x%llx\n", rmp_base, rmp_end);
		return 1;
	}

	/*
	 * Check if SEV-SNP is already enabled, this can happen if we are coming from
	 * kexec boot.
	 */
	rdmsrl(MSR_AMD64_SYSCFG, val);
	if (val & MSR_AMD64_SYSCFG_SNP_EN)
		goto skip_enable;

	/* Initialize the RMP table to zero */
	memset(start, 0, sz);

	/* Flush the caches to ensure that data is written before SNP is enabled. */
	wbinvd_on_all_cpus();

	/* Enable SNP on all CPUs. */
	on_each_cpu(snp_enable, NULL, 1);

skip_enable:
	rmptable_start = (unsigned long)start;
	rmptable_end = rmptable_start + sz;

	pr_info("RMP table physical address 0x%016llx - 0x%016llx\n", rmp_base, rmp_end);

	return 0;
}

static int __init snp_rmptable_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_SEV_SNP))
		return 0;

	/*
	 * The SEV-SNP support requires that IOMMU must be enabled, and is not
	 * configured in the passthrough mode.
	 */
	if (no_iommu || iommu_default_passthrough()) {
		setup_clear_cpu_cap(X86_FEATURE_SEV_SNP);
		pr_err("IOMMU is either disabled or configured in passthrough mode.\n");
		return 0;
	}

	if (__snp_rmptable_init()) {
		setup_clear_cpu_cap(X86_FEATURE_SEV_SNP);
		return 1;
	}

	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "x86/rmptable_init:online", __snp_enable, NULL);

	return 0;
}

/*
 * This must be called after the PCI subsystem. This is because before enabling
 * the SNP feature we need to ensure that IOMMU is not configured in the
 * passthrough mode. The iommu_default_passthrough() is used for checking the
 * passthough state, and it is available after subsys_initcall().
 */
fs_initcall(snp_rmptable_init);

struct rmpentry *snp_lookup_page_in_rmptable(struct page *page, int *level)
{
	unsigned long phys = page_to_pfn(page) << PAGE_SHIFT;
	struct rmpentry *entry, *large_entry;
	unsigned long vaddr;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return NULL;

	vaddr = rmptable_start + rmptable_page_offset(phys);
	if (unlikely(vaddr > rmptable_end))
		return NULL;

	entry = (struct rmpentry *)vaddr;

	/* Read a large RMP entry to get the correct page level used in RMP entry. */
	vaddr = rmptable_start + rmptable_page_offset(phys & PMD_MASK);
	large_entry = (struct rmpentry *)vaddr;
	*level = RMP_TO_X86_PG_LEVEL(rmpentry_pagesize(large_entry));

	return entry;
}
EXPORT_SYMBOL_GPL(snp_lookup_page_in_rmptable);

int psmash(struct page *page)
{
	unsigned long spa = page_to_pfn(page) << PAGE_SHIFT;
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return -ENXIO;

	/* Retry if another processor is modifying the RMP entry. */
	do {
		/* Binutils version 2.36 supports the PSMASH mnemonic. */
		asm volatile(".byte 0xF3, 0x0F, 0x01, 0xFF"
			      : "=a"(ret)
			      : "a"(spa)
			      : "memory", "cc");
	} while (ret == FAIL_INUSE);

	return ret;
}
EXPORT_SYMBOL_GPL(psmash);

int rmpupdate(struct page *page, struct rmpupdate *val)
{
	unsigned long spa = page_to_pfn(page) << PAGE_SHIFT;
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return -ENXIO;

	ret = set_memory_4k((unsigned long)page_to_virt(page), 1);
	if (ret) {
		pr_err("Failed to split physical address 0x%lx (%d)\n", spa, ret);
		return ret;
	}

	/* Retry if another processor is modifying the RMP entry. */
	do {
		/* Binutils version 2.36 supports the RMPUPDATE mnemonic. */
		asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
			     : "=a"(ret)
			     : "a"(spa), "c"((unsigned long)val)
			     : "memory", "cc");
	} while (ret == FAIL_INUSE);

	return ret;
}
EXPORT_SYMBOL_GPL(rmpupdate);
