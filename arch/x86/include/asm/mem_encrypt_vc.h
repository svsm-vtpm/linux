/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#ifndef __X86_MEM_ENCRYPT_VC_H__
#define __X86_MEM_ENCRYPT_VC_H__

#include <linux/types.h>

#ifdef CONFIG_AMD_MEM_ENCRYPT

extern unsigned char early_ghcb[PAGE_SIZE];

void __init early_ghcb_init(void);
void __init ghcb_init(void);

#else

void __init early_ghcb_init(void) { }
void __init ghcb_init(void) { }

#endif	/* CONFIG_AMD_MEM_ENCRYPT */

#endif	/* __X86_MEM_ENCRYPT_VC_H__ */
