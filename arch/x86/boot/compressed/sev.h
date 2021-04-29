/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Secure Encrypted Virtualization
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#ifndef BOOT_COMPRESSED_SEV_H
#define BOOT_COMPRESSED_SEV_H

#ifdef CONFIG_AMD_MEM_ENCRYPT

void snp_set_page_private(unsigned long paddr);
void snp_set_page_shared(unsigned long paddr);

#else

static inline void snp_set_page_private(unsigned long paddr) { }
static inline void snp_set_page_shared(unsigned long paddr) { }

#endif /* CONFIG_AMD_MEM_ENCRYPT */

#endif /* BOOT_COMPRESSED_SEV_H */
