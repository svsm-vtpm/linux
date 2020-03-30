// SPDX-License-Identifier: GPL-2.0
/*
 * AMD SEV SNP support
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 */

#include <asm/sev-es.h>
#include "../../kernel/sev-snp-shared.c"

static inline int asm_pvalidate(unsigned long vaddr, int psize, int validate)
{
	int rc;

	asm volatile(".byte 0xF2,0x0F,0x01,0xFF\n"
		: "=a"(rc)
		: "a"(vaddr), "c"(psize), "d"(validate) : "memory");

	return rc;
}

static int sev_snp_set_memory_private(unsigned long paddr, unsigned long sz)
{
	unsigned long rmp_psize, psize, pshift;
	u64 val, oldmsr;

	/* SNP is not enabled then do nothing */
	if (!sev_snp_enabled())
		return 0;

	pshift = 12;
	psize =  (1 << pshift);
	rmp_psize = 0;	/* hardcode to 4K */

	/* save the current GHCB MSR value */
	oldmsr = sev_snp_rd_ghcb_msr();

	/*
	 * Use the GHCB protocal to issue mem_op to make the page shared.
	 */
	val = GHCB_SNP_MEM_OP_PRIVATE_REQ;
	val |= (paddr >> pshift) << GHCB_SNP_MEM_OP_GFN_RSHIFT;
	val |= rmp_psize << GHCB_SNP_MEM_OP_PSIZE_RSHIFT;

	sev_snp_wr_ghcb_msr(val);
	VMGEXIT();

	/* we are identity mapped, vaddr == paddr */
	if (asm_pvalidate(paddr, 0, 1)) {
		/*
		 * For now, just halt the machine. That makes debugging easier,
		 * later we just call sev_es_terminate() here.
		 */
		while (true)
			asm volatile("hlt\n");
	}

	/* restore the value */
	sev_snp_wr_ghcb_msr(oldmsr);
	return 0;
}
