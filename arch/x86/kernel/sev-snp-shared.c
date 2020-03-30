// SPDX-License-Identifier: GPL-2.0
/*
 * AMD SEV SNP support
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * This file is not compiled stand-alone. It contains code shared
 * between the pre-decompression boot code and the running Linux kernel
 * and is included directly into both code-bases. The function in this
 * file should be called from identity mapped code. 
 */

/* SEV STATUS MSR */
#include <asm/msr-index.h>

#include <asm/sev-es.h>

static bool sev_snp_enabled(void)
{
	unsigned long low, high;
	u64 val;

	asm volatile("rdmsr\n" : "=a" (low), "=d" (high) :
			"c" (MSR_AMD64_SEV));

	val = (high << 32) | low;

	if (val & MSR_AMD64_SEV_SNP_ENABLED)
		return true;

	return false;
}

static inline u64 sev_snp_rd_ghcb_msr(void)
{
	unsigned long low, high;

	asm volatile("rdmsr\n" : "=a" (low), "=d" (high) :
			"c" (MSR_AMD64_SEV_ES_GHCB));

	return ((high << 32) | low);
}

static inline void sev_snp_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = val & 0xffffffffUL;
	high = val >> 32;

	asm volatile("wrmsr\n" : : "c" (MSR_AMD64_SEV_ES_GHCB),
			"a"(low), "d" (high) : "memory");
}

static int sev_snp_set_memory_shared(unsigned long paddr, unsigned long sz)
{
	unsigned long paddr_end;
	unsigned long rmp_psize, psize, pshift;
	u64 val, oldmsr;

	/* SNP is not enabled then do nothing */
	if (!sev_snp_enabled())
		return 0;

	pshift = 12;
	psize =  (1 << pshift);
	paddr_end = paddr + sz;
	rmp_psize = 0;	/* hardcode to 4K */

	/* save the current GHCB MSR value */
	oldmsr = sev_snp_rd_ghcb_msr();

	/*
	 * Use the GHCB protocal to issue mem_op to make the page shared.
	 */
	for (; paddr_end > paddr; paddr += psize) {
		unsigned long pfn = paddr >> pshift;

		val = GHCB_SNP_MEM_OP_SHARED_REQ;
		val |= pfn  << GHCB_SNP_MEM_OP_GFN_RSHIFT;
		val |= rmp_psize << GHCB_SNP_MEM_OP_PSIZE_RSHIFT;

		sev_snp_wr_ghcb_msr(val);
		VMGEXIT();
	}

	/* restore the value */
	sev_snp_wr_ghcb_msr(oldmsr);
	return 0;
}
