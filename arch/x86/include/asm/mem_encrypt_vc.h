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

#ifndef __X86_MEM_ENCRYPT_VC_H__
#define __X86_MEM_ENCRYPT_VC_H__

#include <linux/types.h>

struct pt_regs;

#ifdef CONFIG_AMD_MEM_ENCRYPT

void __init early_ghcb_init(void);
void __init ghcb_init(void);

int sev_es_vc_exception(struct pt_regs *regs, long error_code);

#else

void __init early_ghcb_init(void) { }
void __init ghcb_init(void) { }

static inline int sev_es_vc_exception(struct pt_regs *regs, long error_code)
{
	return 0;
}

#endif	/* CONFIG_AMD_MEM_ENCRYPT */

#endif	/* __X86_MEM_ENCRYPT_VC_H__ */
