/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2020 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */
#ifndef __X86_RMPTABLE_H__
#define __X86_RMPTABLE_H__

#define RMPUPDATE	".byte 0xF2, 0x0F, 0x01, 0xFE"

/* Return code of RMPUPDATE */
#define RMPUPDATE_SUCCESS		0
#define RMPUPDATE_FAIL_INPUT		1
#define RMPUPDATE_FAIL_PERMISSION	2
#define RMPUPDATE_FAIL_INUSE		3
#define RMPUPDATE_FAIL_OVERLAP		4

#define RMP_PG_SIZE_2M 		1
#define RMP_PG_SIZE_4K 		0

#ifdef CONFIG_AMD_MEM_ENCRYPT
#include <linux/jump_label.h>

extern struct static_key_false snp_enable_key;
static inline bool snp_key_active(void)
{
	return static_branch_unlikely(&snp_enable_key);
}

#else /* !CONFIG_AMD_MEM_ENCRYPT */

static inline bool snp_key_active(void) { return false; }

#endif /* CONFIG_AMD_MEM_ENCRYPT */

struct rmpupdate {
	u64 gpa;
	u8 assigned;
	u8 pagesize;
	u8 immutable;
	u8 rsvd;
	u32 asid;
} __packed;

static inline int rmptable_update(u64 spa, struct rmpupdate *val)
{
	bool flush = true;
	int ret;

	if (!snp_key_active())
		return -ENXIO;

	asm volatile(RMPUPDATE
		     : "=a"(ret)
		     : "a"(spa), "c"((unsigned long)val), "d"(flush) : "memory");

	return ret;
}

#define PSMASH	".byte 0xF3, 0x0F, 0x01, 0xFF"

/* Return code of PSMASH */
#define PSMASH_FAIL_INPUT		1
#define PSMASH_FAIL_PERMISSION		2
#define PSMASH_FAIL_INUSE		3
#define PSMASH_FAIL_BADADDR		4

static inline int rmptable_psmash(u64 spa)
{
	int ret;

	if (!snp_key_active())
		return -ENXIO;

	asm volatile(PSMASH
		     : "=a"(ret)
		     : "a"(spa) : "memory");

	return ret;
}

#define PVALIDATE  ".byte 0xF2, 0x0F, 0x01, 0xFF"

/* Return code of PVALIDATE */
#define PVALIDATE_SUCCESS		0
#define PVALIDATE_FAIL_INPUT		1
#define PVALIDATE_FAIL_SIZEMISMATCH	6

static inline int address_pvalidate(unsigned long vaddr, int psize, int validate)
{
	int rc;

	asm volatile(PVALIDATE
		: "=a"(rc)
		: "a"(vaddr), "c"(psize), "d"(validate) : "memory");

	return rc;
}

#define RMPTABLE_RSVD_BYTES	(16 * 1024)
#define RMPTABLE_ENTRY_SZ	16

static inline unsigned long rmptable_page_offset(unsigned long spa)
{
	return RMPTABLE_RSVD_BYTES + (RMPTABLE_ENTRY_SZ * (spa >> PAGE_SHIFT));
}

#define RMP_X86_PG_LEVEL(x)	(((x) == RMP_PG_SIZE_4K) ? PG_LEVEL_4K : PG_LEVEL_2M)
#define X86_RMP_PG_LEVEL(x)	(((x) == PG_LEVEL_4K) ? RMP_PG_SIZE_4K : RMP_PG_SIZE_2M)

struct rmpentry {
	u64 gpa;
	u8 assigned;
	u8 pagesize;  /* RMP page size */
	u8 immutable;
	u8 pagelevel; /* x86 page level */
	u32 asid;
};

int lookup_address_in_rmptable(u64 spa, struct rmpentry *e);

#endif /* __X86_RMPTABLE_H__ */
