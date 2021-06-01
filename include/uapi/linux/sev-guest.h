/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Userspace interface for AMD SEV and SEV-SNP guest driver.
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * SEV-SNP API specification is available at: https://developer.amd.com/sev/
 */

#ifndef __UAPI_LINUX_SEV_GUEST_H_
#define __UAPI_LINUX_SEV_GUEST_H_

#include <linux/types.h>

struct snp_user_report_req {
	__u8 user_data[64];
};

struct snp_user_report {
	struct snp_user_report_req req;

	/* see SEV-SNP spec for the response format */
	__u8 response[4000];
};

struct snp_user_derive_key_req {
	__u8 root_key_select;
	__u64 guest_field_select;
	__u32 vmpl;
	__u32 guest_svn;
	__u64 tcb_version;
};

struct snp_user_derive_key {
	struct snp_user_derive_key_req req;

	/* see SEV-SNP spec for the response format */
	__u8 response[64];
};

struct snp_user_guest_request {
	/* Message version number (must be non-zero) */
	__u8 msg_version;
	__u64 data;

	/* firmware error code on failure (see psp-sev.h) */
	__u32 fw_err;
};

#define SNP_GUEST_REQ_IOC_TYPE	'S'
#define SNP_GET_REPORT _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x0, struct snp_user_guest_request)
#define SNP_DERIVE_KEY _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x1, struct snp_user_guest_request)

#endif /* __UAPI_LINUX_SEV_GUEST_H_ */
