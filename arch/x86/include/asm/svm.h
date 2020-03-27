/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SVM_H
#define __SVM_H

#include <linux/bug.h>
#include <linux/kvm_host.h>

#include <uapi/asm/svm.h>


enum {
	INTERCEPT_INTR,
	INTERCEPT_NMI,
	INTERCEPT_SMI,
	INTERCEPT_INIT,
	INTERCEPT_VINTR,
	INTERCEPT_SELECTIVE_CR0,
	INTERCEPT_STORE_IDTR,
	INTERCEPT_STORE_GDTR,
	INTERCEPT_STORE_LDTR,
	INTERCEPT_STORE_TR,
	INTERCEPT_LOAD_IDTR,
	INTERCEPT_LOAD_GDTR,
	INTERCEPT_LOAD_LDTR,
	INTERCEPT_LOAD_TR,
	INTERCEPT_RDTSC,
	INTERCEPT_RDPMC,
	INTERCEPT_PUSHF,
	INTERCEPT_POPF,
	INTERCEPT_CPUID,
	INTERCEPT_RSM,
	INTERCEPT_IRET,
	INTERCEPT_INTn,
	INTERCEPT_INVD,
	INTERCEPT_PAUSE,
	INTERCEPT_HLT,
	INTERCEPT_INVLPG,
	INTERCEPT_INVLPGA,
	INTERCEPT_IOIO_PROT,
	INTERCEPT_MSR_PROT,
	INTERCEPT_TASK_SWITCH,
	INTERCEPT_FERR_FREEZE,
	INTERCEPT_SHUTDOWN,
	INTERCEPT_VMRUN,
	INTERCEPT_VMMCALL,
	INTERCEPT_VMLOAD,
	INTERCEPT_VMSAVE,
	INTERCEPT_STGI,
	INTERCEPT_CLGI,
	INTERCEPT_SKINIT,
	INTERCEPT_RDTSCP,
	INTERCEPT_ICEBP,
	INTERCEPT_WBINVD,
	INTERCEPT_MONITOR,
	INTERCEPT_MWAIT,
	INTERCEPT_MWAIT_COND,
	INTERCEPT_XSETBV,
	INTERCEPT_RDPRU,
};


struct __attribute__ ((__packed__)) vmcb_control_area {
	u32 intercept_cr;
	u32 intercept_dr;
	u32 intercept_exceptions;
	u64 intercept;
	u8 reserved_1[40];
	u16 pause_filter_thresh;
	u16 pause_filter_count;
	u64 iopm_base_pa;
	u64 msrpm_base_pa;
	u64 tsc_offset;
	u32 asid;
	u8 tlb_ctl;
	u8 reserved_2[3];
	u32 int_ctl;
	u32 int_vector;
	u32 int_state;
	u8 reserved_3[4];
	u32 exit_code;
	u32 exit_code_hi;
	u64 exit_info_1;
	u64 exit_info_2;
	u32 exit_int_info;
	u32 exit_int_info_err;
	u64 nested_ctl;
	u64 avic_vapic_bar;
	u64 ghcb_gpa;
	u32 event_inj;
	u32 event_inj_err;
	u64 nested_cr3;
	u64 virt_ext;
	u32 clean;
	u32 reserved_5;
	u64 next_rip;
	u8 insn_len;
	u8 insn_bytes[15];
	u64 avic_backing_page;	/* Offset 0xe0 */
	u8 reserved_6[8];	/* Offset 0xe8 */
	u64 avic_logical_id;	/* Offset 0xf0 */
	u64 avic_physical_id;	/* Offset 0xf8 */
	u8 reserved_7[8];
	u64 vmsa_pa;		/* Used for an SEV-ES guest */
	u8 reserved_8[752];
};


#define TLB_CONTROL_DO_NOTHING 0
#define TLB_CONTROL_FLUSH_ALL_ASID 1
#define TLB_CONTROL_FLUSH_ASID 3
#define TLB_CONTROL_FLUSH_ASID_LOCAL 7

#define V_TPR_MASK 0x0f

#define V_IRQ_SHIFT 8
#define V_IRQ_MASK (1 << V_IRQ_SHIFT)

#define V_GIF_SHIFT 9
#define V_GIF_MASK (1 << V_GIF_SHIFT)

#define V_INTR_PRIO_SHIFT 16
#define V_INTR_PRIO_MASK (0x0f << V_INTR_PRIO_SHIFT)

#define V_IGN_TPR_SHIFT 20
#define V_IGN_TPR_MASK (1 << V_IGN_TPR_SHIFT)

#define V_INTR_MASKING_SHIFT 24
#define V_INTR_MASKING_MASK (1 << V_INTR_MASKING_SHIFT)

#define V_GIF_ENABLE_SHIFT 25
#define V_GIF_ENABLE_MASK (1 << V_GIF_ENABLE_SHIFT)

#define AVIC_ENABLE_SHIFT 31
#define AVIC_ENABLE_MASK (1 << AVIC_ENABLE_SHIFT)

#define LBR_CTL_ENABLE_MASK BIT_ULL(0)
#define VIRTUAL_VMLOAD_VMSAVE_ENABLE_MASK BIT_ULL(1)

#define SVM_INTERRUPT_SHADOW_MASK	BIT_ULL(0)
#define SVM_GUEST_INTERRUPT_MASK	BIT_ULL(1)

#define SVM_IOIO_STR_SHIFT 2
#define SVM_IOIO_REP_SHIFT 3
#define SVM_IOIO_SIZE_SHIFT 4
#define SVM_IOIO_ASIZE_SHIFT 7

#define SVM_IOIO_TYPE_MASK 1
#define SVM_IOIO_STR_MASK (1 << SVM_IOIO_STR_SHIFT)
#define SVM_IOIO_REP_MASK (1 << SVM_IOIO_REP_SHIFT)
#define SVM_IOIO_SIZE_MASK (7 << SVM_IOIO_SIZE_SHIFT)
#define SVM_IOIO_ASIZE_MASK (7 << SVM_IOIO_ASIZE_SHIFT)

#define SVM_VM_CR_VALID_MASK	0x001fULL
#define SVM_VM_CR_SVM_LOCK_MASK 0x0008ULL
#define SVM_VM_CR_SVM_DIS_MASK  0x0010ULL

#define SVM_NESTED_CTL_NP_ENABLE	BIT(0)
#define SVM_NESTED_CTL_SEV_ENABLE	BIT(1)
#define SVM_NESTED_CTL_SEV_ES_ENABLE	BIT(2)

struct __attribute__ ((__packed__)) vmcb_seg {
	u16 selector;
	u16 attrib;
	u32 limit;
	u64 base;
};

struct __attribute__ ((__packed__)) vmcb_save_area {
	struct vmcb_seg es;
	struct vmcb_seg cs;
	struct vmcb_seg ss;
	struct vmcb_seg ds;
	struct vmcb_seg fs;
	struct vmcb_seg gs;
	struct vmcb_seg gdtr;
	struct vmcb_seg ldtr;
	struct vmcb_seg idtr;
	struct vmcb_seg tr;
	u8 reserved_1[43];
	u8 cpl;
	u8 reserved_2[4];
	u64 efer;
	u8 reserved_3[112];
	u64 cr4;
	u64 cr3;
	u64 cr0;
	u64 dr7;
	u64 dr6;
	u64 rflags;
	u64 rip;
	u8 reserved_4[88];
	u64 rsp;
	u8 reserved_5[24];
	u64 rax;
	u64 star;
	u64 lstar;
	u64 cstar;
	u64 sfmask;
	u64 kernel_gs_base;
	u64 sysenter_cs;
	u64 sysenter_esp;
	u64 sysenter_eip;
	u64 cr2;
	u8 reserved_6[32];
	u64 g_pat;
	u64 dbgctl;
	u64 br_from;
	u64 br_to;
	u64 last_excp_from;
	u64 last_excp_to;

	/*
	 * The following part of the save area is valid only for
	 * SEV-ES guests when referenced through the GHCB.
	 */
	u8 reserved_7[104];
	u64 reserved_8;		/* rax already available at 0x01f8 */
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 reserved_9;		/* rsp already available at 0x01d8 */
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u8 reserved_10[16];
	u64 sw_exit_code;
	u64 sw_exit_info_1;
	u64 sw_exit_info_2;
	u64 sw_scratch;
	u8 reserved_11[56];
	u64 xcr0;
	u8 valid_bitmap[16];
	u64 x87_state_gpa;
	u8 reserved_12[1016];
};

#define GHCB_VERSION_MAX		1ULL
#define GHCB_VERSION_MIN		1ULL

#define GHCB_USAGE_STANDARD		0

#define GHCB_MSR_INFO_POS		0
#define GHCB_MSR_INFO_MASK		((1 << 12) - 1)

#define GHCB_MSR_SEV_INFO_RESP		0x001
#define GHCB_MSR_SEV_INFO_REQ		0x002
#define GHCB_MSR_VER_MAX_POS		48
#define GHCB_MSR_VER_MAX_MASK		0xffff
#define GHCB_MSR_VER_MIN_POS		32
#define GHCB_MSR_VER_MIN_MASK		0xffff
#define GHCB_MSR_CBIT_POS		24
#define GHCB_MSR_CBIT_MASK		0xff
#define GHCB_MSR_SEV_INFO(_max, _min, _cbit)				\
	((((_max) & GHCB_MSR_VER_MAX_MASK) << GHCB_MSR_VER_MAX_POS) |	\
	 (((_min) & GHCB_MSR_VER_MIN_MASK) << GHCB_MSR_VER_MIN_POS) |	\
	 (((_cbit) & GHCB_MSR_CBIT_MASK) << GHCB_MSR_CBIT_POS) |	\
	 GHCB_MSR_SEV_INFO_RESP)

#define GHCB_MSR_CPUID_REQ		0x004
#define GHCB_MSR_CPUID_RESP		0x005
#define GHCB_MSR_CPUID_FUNC_POS		32
#define GHCB_MSR_CPUID_FUNC_MASK	0xffffffff
#define GHCB_MSR_CPUID_VALUE_POS	32
#define GHCB_MSR_CPUID_VALUE_MASK	0xffffffff
#define GHCB_MSR_CPUID_REG_POS		30
#define GHCB_MSR_CPUID_REG_MASK		0x3

#define GHCB_MSR_TERM_REQ		0x100
#define GHCB_MSR_TERM_REASON_SET_POS	12
#define GHCB_MSR_TERM_REASON_SET_MASK	0xf
#define GHCB_MSR_TERM_REASON_POS	16
#define GHCB_MSR_TERM_REASON_MASK	0xff

struct __attribute__ ((__packed__)) ghcb {
	struct vmcb_save_area save;

	u8 shared_buffer[2032];

	u8 reserved_1[10];
	u16 protocol_version;	/* negotiated SEV-ES/GHCB protocol version */
	u32 ghcb_usage;
};

struct __attribute__ ((__packed__)) vmcb {
	struct vmcb_control_area control;
	struct vmcb_save_area save;
};

#define SVM_CPUID_FUNC 0x8000000a

#define SVM_VM_CR_SVM_DISABLE 4

#define SVM_SELECTOR_S_SHIFT 4
#define SVM_SELECTOR_DPL_SHIFT 5
#define SVM_SELECTOR_P_SHIFT 7
#define SVM_SELECTOR_AVL_SHIFT 8
#define SVM_SELECTOR_L_SHIFT 9
#define SVM_SELECTOR_DB_SHIFT 10
#define SVM_SELECTOR_G_SHIFT 11

#define SVM_SELECTOR_TYPE_MASK (0xf)
#define SVM_SELECTOR_S_MASK (1 << SVM_SELECTOR_S_SHIFT)
#define SVM_SELECTOR_DPL_MASK (3 << SVM_SELECTOR_DPL_SHIFT)
#define SVM_SELECTOR_P_MASK (1 << SVM_SELECTOR_P_SHIFT)
#define SVM_SELECTOR_AVL_MASK (1 << SVM_SELECTOR_AVL_SHIFT)
#define SVM_SELECTOR_L_MASK (1 << SVM_SELECTOR_L_SHIFT)
#define SVM_SELECTOR_DB_MASK (1 << SVM_SELECTOR_DB_SHIFT)
#define SVM_SELECTOR_G_MASK (1 << SVM_SELECTOR_G_SHIFT)

#define SVM_SELECTOR_WRITE_MASK (1 << 1)
#define SVM_SELECTOR_READ_MASK SVM_SELECTOR_WRITE_MASK
#define SVM_SELECTOR_CODE_MASK (1 << 3)

#define INTERCEPT_CR0_READ	0
#define INTERCEPT_CR3_READ	3
#define INTERCEPT_CR4_READ	4
#define INTERCEPT_CR8_READ	8
#define INTERCEPT_CR0_WRITE	(16 + 0)
#define INTERCEPT_CR3_WRITE	(16 + 3)
#define INTERCEPT_CR4_WRITE	(16 + 4)
#define INTERCEPT_CR8_WRITE	(16 + 8)

#define INTERCEPT_DR0_READ	0
#define INTERCEPT_DR1_READ	1
#define INTERCEPT_DR2_READ	2
#define INTERCEPT_DR3_READ	3
#define INTERCEPT_DR4_READ	4
#define INTERCEPT_DR5_READ	5
#define INTERCEPT_DR6_READ	6
#define INTERCEPT_DR7_READ	7
#define INTERCEPT_DR0_WRITE	(16 + 0)
#define INTERCEPT_DR1_WRITE	(16 + 1)
#define INTERCEPT_DR2_WRITE	(16 + 2)
#define INTERCEPT_DR3_WRITE	(16 + 3)
#define INTERCEPT_DR4_WRITE	(16 + 4)
#define INTERCEPT_DR5_WRITE	(16 + 5)
#define INTERCEPT_DR6_WRITE	(16 + 6)
#define INTERCEPT_DR7_WRITE	(16 + 7)

#define SVM_EVTINJ_VEC_MASK 0xff

#define SVM_EVTINJ_TYPE_SHIFT 8
#define SVM_EVTINJ_TYPE_MASK (7 << SVM_EVTINJ_TYPE_SHIFT)

#define SVM_EVTINJ_TYPE_INTR (0 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_NMI (2 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_EXEPT (3 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_SOFT (4 << SVM_EVTINJ_TYPE_SHIFT)

#define SVM_EVTINJ_VALID (1 << 31)
#define SVM_EVTINJ_VALID_ERR (1 << 11)

#define SVM_EXITINTINFO_VEC_MASK SVM_EVTINJ_VEC_MASK
#define SVM_EXITINTINFO_TYPE_MASK SVM_EVTINJ_TYPE_MASK

#define	SVM_EXITINTINFO_TYPE_INTR SVM_EVTINJ_TYPE_INTR
#define	SVM_EXITINTINFO_TYPE_NMI SVM_EVTINJ_TYPE_NMI
#define	SVM_EXITINTINFO_TYPE_EXEPT SVM_EVTINJ_TYPE_EXEPT
#define	SVM_EXITINTINFO_TYPE_SOFT SVM_EVTINJ_TYPE_SOFT

#define SVM_EXITINTINFO_VALID SVM_EVTINJ_VALID
#define SVM_EXITINTINFO_VALID_ERR SVM_EVTINJ_VALID_ERR

#define SVM_EXITINFOSHIFT_TS_REASON_IRET 36
#define SVM_EXITINFOSHIFT_TS_REASON_JMP 38
#define SVM_EXITINFOSHIFT_TS_HAS_ERROR_CODE 44

#define SVM_EXITINFO_REG_MASK 0x0F

#define SVM_CR0_SELECTIVE_MASK (X86_CR0_TS | X86_CR0_MP)

static const u32 host_save_user_msrs[] = {
#ifdef CONFIG_X86_64
	MSR_STAR, MSR_LSTAR, MSR_CSTAR, MSR_SYSCALL_MASK, MSR_KERNEL_GS_BASE,
	MSR_FS_BASE,
#endif
	MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, MSR_IA32_SYSENTER_EIP,
	MSR_TSC_AUX,
};

#define NR_HOST_SAVE_USER_MSRS ARRAY_SIZE(host_save_user_msrs)

struct kvm_sev_info {
	bool active;		/* SEV enabled guest */
	bool es_active;		/* SEV-ES enabled guest */
	unsigned int asid;	/* ASID used for this guest */
	unsigned int handle;	/* SEV firmware handle */
	int fd;			/* SEV device fd */
	unsigned long pages_locked; /* Number of pages locked */
	struct list_head regions_list;  /* List of registered regions */
};

struct kvm_svm {
	struct kvm kvm;

	/* Struct members for AVIC */
	u32 avic_vm_id;
	struct page *avic_logical_id_table_page;
	struct page *avic_physical_id_table_page;
	struct hlist_node hnode;

	struct kvm_sev_info sev_info;
};

struct nested_state {
	struct vmcb *hsave;
	u64 hsave_msr;
	u64 vm_cr_msr;
	u64 vmcb;

	/* These are the merged vectors */
	u32 *msrpm;

	/* gpa pointers to the real vectors */
	u64 vmcb_msrpm;
	u64 vmcb_iopm;

	/* A VMEXIT is required but not yet emulated */
	bool exit_required;

	/* cache for intercepts of the guest */
	u32 intercept_cr;
	u32 intercept_dr;
	u32 intercept_exceptions;
	u64 intercept;

	/* Nested Paging related state */
	u64 nested_cr3;
};

struct vcpu_svm {
	struct kvm_vcpu vcpu;
	struct vmcb *vmcb;
	unsigned long vmcb_pa;
	struct svm_cpu_data *svm_data;
	uint64_t asid_generation;
	uint64_t sysenter_esp;
	uint64_t sysenter_eip;
	uint64_t tsc_aux;

	u64 msr_decfg;

	u64 next_rip;

	u64 host_user_msrs[NR_HOST_SAVE_USER_MSRS];
	struct {
		u16 fs;
		u16 gs;
		u16 ldt;
		u64 gs_base;
	} host;

	u64 spec_ctrl;
	/*
	 * Contains guest-controlled bits of VIRT_SPEC_CTRL, which will be
	 * translated into the appropriate L2_CFG bits on the host to
	 * perform speculative control.
	 */
	u64 virt_spec_ctrl;

	u32 *msrpm;

	ulong nmi_iret_rip;

	struct nested_state nested;

	bool nmi_singlestep;
	u64 nmi_singlestep_guest_rflags;

	unsigned int3_injected;
	unsigned long int3_rip;

	/* cached guest cpuid flags for faster access */
	bool nrips_enabled	: 1;

	u32 ldr_reg;
	u32 dfr_reg;
	struct page *avic_backing_page;
	u64 *avic_physical_id_cache;
	bool avic_is_running;

	/*
	 * Per-vcpu list of struct amd_svm_iommu_ir:
	 * This is used mainly to store interrupt remapping information used
	 * when update the vcpu affinity. This avoids the need to scan for
	 * IRTE and try to match ga_tag in the IOMMU driver.
	 */
	struct list_head ir_list;
	spinlock_t ir_list_lock;

	/* which host CPU was used for running this vcpu */
	unsigned int last_cpu;

	/* SEV-ES support */
	struct vmcb_save_area *vmsa;
	struct ghcb *ghcb;
	bool ghcb_active;

	/* SEV-ES scratch area support */
	void *ghcb_sa;
	u64 ghcb_sa_len;
	bool ghcb_sa_sync;
	bool ghcb_sa_free;
};

#define __sme_page_pa(x) __sme_set(page_to_pfn(x) << PAGE_SHIFT)

struct enc_region {
	struct list_head list;
	unsigned long npages;
	struct page **pages;
	unsigned long uaddr;
	unsigned long size;
};

static inline struct kvm_svm *to_kvm_svm(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_svm, kvm);
}

static inline bool sev_guest(struct kvm *kvm)
{
#ifdef CONFIG_KVM_AMD_SEV
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return sev->active;
#else
	return false;
#endif
}

static inline bool sev_es_guest(struct kvm *kvm)
{
#ifdef CONFIG_KVM_AMD_SEV
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return sev_guest(kvm) && sev->es_active;
#else
	return false;
#endif
}

static inline int sev_get_asid(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return sev->asid;
}

static inline struct vmcb_save_area *get_vmsa(struct vcpu_svm *svm)
{
	struct vmcb_save_area *vmsa;

	if (sev_es_guest(svm->vcpu.kvm)) {
		/*
		 * Before LAUNCH_UPDATE_VMSA, use the actual SEV-ES save
		 * area to construct the initial state.  Afterwards, use
		 * the GHCB.
		 */
		if (svm->vcpu.arch.vmsa_encrypted)
			vmsa = &svm->ghcb->save;
		else
			vmsa = svm->vmsa;
	} else {
		vmsa = &svm->vmcb->save;
	}

	return vmsa;
}

/* VMSA / GHCB Accessor functions */

#define DEFINE_GHCB_INDICES(field)					\
	u16 idx = offsetof(struct vmcb_save_area, field) / 8;		\
	u16 byte_idx  = idx / 8;					\
	u16 bit_idx   = idx % 8;					\
	BUILD_BUG_ON(byte_idx > ARRAY_SIZE(vmsa->valid_bitmap));

#define DEFINE_GHCB_VMSA_SEGMENT_ENTRY(field, entry, size)		\
	static inline void						\
	ghcb_set_##field##_##entry(struct ghcb *ghcb, size value)	\
	{								\
		struct vmcb_save_area *vmsa = &((ghcb)->save);		\
		DEFINE_GHCB_INDICES(field)				\
									\
		vmsa->field.entry = value;				\
		vmsa->valid_bitmap[byte_idx] |= BIT(bit_idx);		\
	}								\
									\
	static inline void						\
	svm_##field##_write_##entry(struct vcpu_svm *svm,		\
				    size value)				\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
		DEFINE_GHCB_INDICES(field)				\
									\
		vmsa->field.entry = value;				\
		if (svm->vcpu.arch.vmsa_encrypted)			\
			vmsa->valid_bitmap[byte_idx] |= BIT(bit_idx);	\
	}								\
									\
	static inline size						\
	svm_##field##_read_##entry(struct vcpu_svm *svm)		\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
									\
		return vmsa->field.entry;				\
	}

#define DEFINE_GHCB_VMSA_SEGMENT_ACCESSOR(field)			\
	DEFINE_GHCB_VMSA_SEGMENT_ENTRY(field, selector, u16)		\
	DEFINE_GHCB_VMSA_SEGMENT_ENTRY(field, attrib, u16)		\
	DEFINE_GHCB_VMSA_SEGMENT_ENTRY(field, limit, u32)		\
	DEFINE_GHCB_VMSA_SEGMENT_ENTRY(field, base, u64)		\
	static inline void						\
	ghcb_set_##field(struct ghcb *ghcb, struct vmcb_seg *seg)	\
	{								\
		struct vmcb_save_area *vmsa = &((ghcb)->save);		\
		DEFINE_GHCB_INDICES(field)				\
									\
		vmsa->field = *seg;					\
		vmsa->valid_bitmap[byte_idx] |= BIT(bit_idx);		\
	}								\
									\
	static inline void						\
	svm_##field##_write(struct vcpu_svm *svm, struct vmcb_seg *seg)	\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
									\
		vmsa->field = *seg;					\
	}

#define DEFINE_GHCB_VMSA_SIZE_ACCESSORS(field, size)			\
	static inline bool						\
	ghcb_is_valid_##field(const struct ghcb *ghcb)			\
	{								\
		const struct vmcb_save_area *vmsa = &((ghcb)->save);	\
		DEFINE_GHCB_INDICES(field)				\
									\
		return !!(vmsa->valid_bitmap[byte_idx] & BIT(bit_idx));	\
	}								\
									\
	static inline void						\
	ghcb_set_##field(struct ghcb *ghcb, size value)			\
	{								\
		struct vmcb_save_area *vmsa = &((ghcb)->save);		\
		DEFINE_GHCB_INDICES(field)				\
									\
		vmsa->field = value;					\
		vmsa->valid_bitmap[byte_idx] |= BIT(bit_idx);		\
	}								\
									\
	static inline size						\
	svm_##field##_read(struct vcpu_svm *svm)			\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
									\
		return vmsa->field;					\
	}								\
									\
	static inline void						\
	svm_##field##_write(struct vcpu_svm *svm, size value)		\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
		DEFINE_GHCB_INDICES(field)				\
									\
		vmsa->field = value;					\
		if (svm->vcpu.arch.vmsa_encrypted)			\
			vmsa->valid_bitmap[byte_idx] |= BIT(bit_idx);	\
	}								\
									\
	static inline void						\
	svm_##field##_and(struct vcpu_svm *svm, size value)		\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
		DEFINE_GHCB_INDICES(field)				\
									\
		vmsa->field &= value;					\
		if (svm->vcpu.arch.vmsa_encrypted)			\
			vmsa->valid_bitmap[byte_idx] |= BIT(bit_idx);	\
	}								\
									\
	static inline void						\
	svm_##field##_or(struct vcpu_svm *svm, size value)		\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
		DEFINE_GHCB_INDICES(field)				\
									\
		vmsa->field |= value;					\
		if (svm->vcpu.arch.vmsa_encrypted)			\
			vmsa->valid_bitmap[byte_idx] |= BIT(bit_idx);	\
	}

#define DEFINE_GHCB_VMSA_ACCESSORS(field)				\
	DEFINE_GHCB_VMSA_SIZE_ACCESSORS(field, u64)

#define DEFINE_GHCB_VMSA_U8_ACCESSORS(field)				\
	DEFINE_GHCB_VMSA_SIZE_ACCESSORS(field, u8)

DEFINE_GHCB_VMSA_SEGMENT_ACCESSOR(cs)
DEFINE_GHCB_VMSA_SEGMENT_ACCESSOR(ds)
DEFINE_GHCB_VMSA_SEGMENT_ACCESSOR(es)
DEFINE_GHCB_VMSA_SEGMENT_ACCESSOR(fs)
DEFINE_GHCB_VMSA_SEGMENT_ACCESSOR(gs)
DEFINE_GHCB_VMSA_SEGMENT_ACCESSOR(ss)
DEFINE_GHCB_VMSA_SEGMENT_ACCESSOR(gdtr)
DEFINE_GHCB_VMSA_SEGMENT_ACCESSOR(idtr)
DEFINE_GHCB_VMSA_SEGMENT_ACCESSOR(ldtr)
DEFINE_GHCB_VMSA_SEGMENT_ACCESSOR(tr)

DEFINE_GHCB_VMSA_ACCESSORS(efer)
DEFINE_GHCB_VMSA_ACCESSORS(cr0)
DEFINE_GHCB_VMSA_ACCESSORS(cr2)
DEFINE_GHCB_VMSA_ACCESSORS(cr3)
DEFINE_GHCB_VMSA_ACCESSORS(cr4)
DEFINE_GHCB_VMSA_ACCESSORS(dr6)
DEFINE_GHCB_VMSA_ACCESSORS(dr7)
DEFINE_GHCB_VMSA_ACCESSORS(rflags)
DEFINE_GHCB_VMSA_ACCESSORS(star)
DEFINE_GHCB_VMSA_ACCESSORS(lstar)
DEFINE_GHCB_VMSA_ACCESSORS(cstar)
DEFINE_GHCB_VMSA_ACCESSORS(sfmask)
DEFINE_GHCB_VMSA_ACCESSORS(kernel_gs_base)
DEFINE_GHCB_VMSA_ACCESSORS(sysenter_cs)
DEFINE_GHCB_VMSA_ACCESSORS(sysenter_esp)
DEFINE_GHCB_VMSA_ACCESSORS(sysenter_eip)
DEFINE_GHCB_VMSA_ACCESSORS(g_pat)
DEFINE_GHCB_VMSA_ACCESSORS(dbgctl)
DEFINE_GHCB_VMSA_ACCESSORS(br_from)
DEFINE_GHCB_VMSA_ACCESSORS(br_to)
DEFINE_GHCB_VMSA_ACCESSORS(last_excp_from)
DEFINE_GHCB_VMSA_ACCESSORS(last_excp_to)

DEFINE_GHCB_VMSA_U8_ACCESSORS(cpl)
DEFINE_GHCB_VMSA_ACCESSORS(rip)
DEFINE_GHCB_VMSA_ACCESSORS(rax)
DEFINE_GHCB_VMSA_ACCESSORS(rbx)
DEFINE_GHCB_VMSA_ACCESSORS(rcx)
DEFINE_GHCB_VMSA_ACCESSORS(rdx)
DEFINE_GHCB_VMSA_ACCESSORS(rsp)
DEFINE_GHCB_VMSA_ACCESSORS(rbp)
DEFINE_GHCB_VMSA_ACCESSORS(rsi)
DEFINE_GHCB_VMSA_ACCESSORS(rdi)
DEFINE_GHCB_VMSA_ACCESSORS(r8)
DEFINE_GHCB_VMSA_ACCESSORS(r9)
DEFINE_GHCB_VMSA_ACCESSORS(r10)
DEFINE_GHCB_VMSA_ACCESSORS(r11)
DEFINE_GHCB_VMSA_ACCESSORS(r12)
DEFINE_GHCB_VMSA_ACCESSORS(r13)
DEFINE_GHCB_VMSA_ACCESSORS(r14)
DEFINE_GHCB_VMSA_ACCESSORS(r15)
DEFINE_GHCB_VMSA_ACCESSORS(sw_exit_code)
DEFINE_GHCB_VMSA_ACCESSORS(sw_exit_info_1)
DEFINE_GHCB_VMSA_ACCESSORS(sw_exit_info_2)
DEFINE_GHCB_VMSA_ACCESSORS(sw_scratch)
DEFINE_GHCB_VMSA_ACCESSORS(xcr0)

/*
 * These return values represent the offset in quad words within the VM save
 * area. This allows them to be accessed by casting the save area to a u64
 * array.
 */
#define VMSA_REG_ENTRY(field) offsetof(struct vmcb_save_area, field) / 8
#define VMSA_REG_UNDEF VMSA_REG_ENTRY(valid_bitmap)
static inline unsigned int vcpu_to_vmsa_entry(enum kvm_reg reg)
{
	switch (reg) {
	case VCPU_REGS_RAX:	return VMSA_REG_ENTRY(rax);
	case VCPU_REGS_RBX:	return VMSA_REG_ENTRY(rbx);
	case VCPU_REGS_RCX:	return VMSA_REG_ENTRY(rcx);
	case VCPU_REGS_RDX:	return VMSA_REG_ENTRY(rdx);
	case VCPU_REGS_RSP:	return VMSA_REG_ENTRY(rsp);
	case VCPU_REGS_RBP:	return VMSA_REG_ENTRY(rbp);
	case VCPU_REGS_RSI:	return VMSA_REG_ENTRY(rsi);
	case VCPU_REGS_RDI:	return VMSA_REG_ENTRY(rdi);
#ifdef CONFIG_X86_64
	case VCPU_REGS_R8:	return VMSA_REG_ENTRY(r8);
	case VCPU_REGS_R9:	return VMSA_REG_ENTRY(r9);
	case VCPU_REGS_R10:	return VMSA_REG_ENTRY(r10);
	case VCPU_REGS_R11:	return VMSA_REG_ENTRY(r11);
	case VCPU_REGS_R12:	return VMSA_REG_ENTRY(r12);
	case VCPU_REGS_R13:	return VMSA_REG_ENTRY(r13);
	case VCPU_REGS_R14:	return VMSA_REG_ENTRY(r14);
	case VCPU_REGS_R15:	return VMSA_REG_ENTRY(r15);
#endif
	case VCPU_REGS_RIP:	return VMSA_REG_ENTRY(rip);
	default:
		WARN_ONCE(1, "unsupported VCPU to VMSA register conversion\n");
		return VMSA_REG_UNDEF;
	}
}

#endif
