/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Secure Encrypted Virtualization (SEV) driver interface
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * SEV API spec is available at https://developer.amd.com/sev
 */

#ifndef __LINUX_SNP_GUEST_H_
#define __LINUX_SNP_GUEST_H_

#include <linux/types.h>

#define MAX_AUTHTAG_LEN		32
#define VMPCK_KEY_LEN		32

/*
 * The secrets page contains 96-bytes of reserved field that can be used by
 * the guest OS. The guest OS uses the area to save the message sequence
 * number for each VMPL level.
 */
struct secrets_guest_priv {
	u64 msg_seqno_0;
	u64 msg_seqno_1;
	u64 msg_seqno_2;
	u64 msg_seqno_3;
	u8 rsvd[64];
} __packed;

/* See the SNP spec secrets page layout section for the structure */
struct snp_data_secrets_layout {
	u32 version;
	u32 imiEn:1;
	u32 rsvd1:31;
	u32 fms;
	u32 rsvd2;
	u8 gosvw[16];
	u8 vmpck0[VMPCK_KEY_LEN];
	u8 vmpck1[VMPCK_KEY_LEN];
	u8 vmpck2[VMPCK_KEY_LEN];
	u8 vmpck3[VMPCK_KEY_LEN];
	struct secrets_guest_priv guest_priv;
	u8 rsvd3[3840];
} __packed;

/* See SNP spec SNP_GUEST_REQUEST section for the structure */
enum msg_type {
	SNP_MSG_TYPE_INVALID = 0,
	SNP_MSG_CPUID_REQ,
	SNP_MSG_CPUID_RSP,
	SNP_MSG_KEY_REQ,
	SNP_MSG_KEY_RSP,
	SNP_MSG_REPORT_REQ,
	SNP_MSG_REPORT_RSP,
	SNP_MSG_EXPORT_REQ,
	SNP_MSG_EXPORT_RSP,
	SNP_MSG_IMPORT_REQ,
	SNP_MSG_IMPORT_RSP,
	SNP_MSG_ABSORB_REQ,
	SNP_MSG_ABSORB_RSP,
	SNP_MSG_VMRK_REQ,
	SNP_MSG_VMRK_RSP,

	SNP_MSG_TYPE_MAX
};

enum aead_algo {
	SNP_AEAD_INVALID,
	SNP_AEAD_AES_256_GCM,
};

struct snp_guest_msg_hdr {
	u8 authtag[MAX_AUTHTAG_LEN];
	u64 msg_seqno;
	u8 rsvd1[8];
	u8 algo;
	u8 hdr_version;
	u16 hdr_sz;
	u8 msg_type;
	u8 msg_version;
	u16 msg_sz;
	u32 rsvd2;
	u8 msg_vmpck;
	u8 rsvd3[35];
} __packed;

struct snp_guest_msg {
	struct snp_guest_msg_hdr hdr;
	u8 payload[4000];
} __packed;

struct snp_msg_report_req {
	u8 data[64];
	u32 vmpl;
	u8 rsvd[28];
} __packed;

enum vmgexit_type {
	SNP_GUEST_REQUEST,
	SNP_EXTENDED_GUEST_REQUEST,

	GUEST_REQUEST_MAX
};

struct snp_guest_request_data {
	unsigned long req_gpa;
	unsigned long resp_gpa;
	unsigned long data_gpa;
	unsigned int data_npages;
};

#ifdef CONFIG_AMD_MEM_ENCRYPT
unsigned long snp_issue_guest_request(int vmgexit_type, struct snp_guest_request_data *input);
#else

static inline unsigned long snp_issue_guest_request(int type, struct snp_guest_request_data *input)
{
	return -ENODEV;
}
#endif /* CONFIG_AMD_MEM_ENCRYPT */
#endif /* __LINUX_SNP_GUEST_H__ */
