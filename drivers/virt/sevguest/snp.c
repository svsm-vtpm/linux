// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Secure Encrypted Virtualization Nested Paging (SEV-SNP) guest request interface
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/set_memory.h>
#include <linux/fs.h>
#include <crypto/aead.h>
#include <linux/scatterlist.h>
#include <linux/sev-guest.h>
#include <uapi/linux/sev-guest.h>

#include "snp.h"

#define DEVICE_NAME	"sev-guest"
#define AAD_LEN		48
#define MSG_HDR_VER	1

struct snp_guest_crypto {
	struct crypto_aead *tfm;
	uint8_t *iv, *authtag;
	int iv_len, a_len;
};

struct snp_guest_dev {
	struct device *dev;
	struct miscdevice misc;

	struct snp_guest_crypto *crypto;
	struct snp_guest_msg *request, *response;
};

static DEFINE_MUTEX(snp_cmd_mutex);

static inline struct snp_guest_dev *to_snp_dev(struct file *file)
{
	struct miscdevice *dev = file->private_data;

	return container_of(dev, struct snp_guest_dev, misc);
}

static struct snp_guest_crypto *init_crypto(struct snp_guest_dev *snp_dev, uint8_t *key,
					    size_t keylen)
{
	struct snp_guest_crypto *crypto;

	crypto = kzalloc(sizeof(*crypto), GFP_KERNEL_ACCOUNT);
	if (!crypto)
		return NULL;

	crypto->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(crypto->tfm))
		goto e_free;

	if (crypto_aead_setkey(crypto->tfm, key, keylen))
		goto e_free_crypto;

	crypto->iv_len = crypto_aead_ivsize(crypto->tfm);
	if (crypto->iv_len < 12) {
		dev_err(snp_dev->dev, "IV length is less than 12.\n");
		goto e_free_crypto;
	}

	crypto->iv = kmalloc(crypto->iv_len, GFP_KERNEL_ACCOUNT);
	if (!crypto->iv)
		goto e_free_crypto;

	if (crypto_aead_authsize(crypto->tfm) > MAX_AUTHTAG_LEN) {
		if (crypto_aead_setauthsize(crypto->tfm, MAX_AUTHTAG_LEN)) {
			dev_err(snp_dev->dev, "failed to set authsize to %d\n", MAX_AUTHTAG_LEN);
			goto e_free_crypto;
		}
	}

	crypto->a_len = crypto_aead_authsize(crypto->tfm);
	crypto->authtag = kmalloc(crypto->a_len, GFP_KERNEL_ACCOUNT);
	if (!crypto->authtag)
		goto e_free_crypto;

	return crypto;

e_free_crypto:
	crypto_free_aead(crypto->tfm);
e_free:
	kfree(crypto->iv);
	kfree(crypto->authtag);
	kfree(crypto);

	return NULL;
}

static void deinit_crypto(struct snp_guest_crypto *crypto)
{
	crypto_free_aead(crypto->tfm);
	kfree(crypto->iv);
	kfree(crypto->authtag);
	kfree(crypto);
}

static int enc_dec_message(struct snp_guest_crypto *crypto, struct snp_guest_msg *msg,
			   uint8_t *src_buf, uint8_t *dst_buf, size_t len, bool enc)
{
	struct snp_guest_msg_hdr *hdr = &msg->hdr;
	struct scatterlist src[3], dst[3];
	DECLARE_CRYPTO_WAIT(wait);
	struct aead_request *req;
	int ret;

	req = aead_request_alloc(crypto->tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	/*
	 * AEAD memory operations:
	 * +------ AAD -------+------- DATA -----+---- AUTHTAG----+
	 * |  msg header      |  plaintext       |  hdr->authtag  |
	 * | bytes 30h - 5Fh  |    or            |                |
	 * |                  |   cipher         |                |
	 * +------------------+------------------+----------------+
	 */
	sg_init_table(src, 3);
	sg_set_buf(&src[0], &hdr->algo, AAD_LEN);
	sg_set_buf(&src[1], src_buf, hdr->msg_sz);
	sg_set_buf(&src[2], hdr->authtag, crypto->a_len);

	sg_init_table(dst, 3);
	sg_set_buf(&dst[0], &hdr->algo, AAD_LEN);
	sg_set_buf(&dst[1], dst_buf, hdr->msg_sz);
	sg_set_buf(&dst[2], hdr->authtag, crypto->a_len);

	aead_request_set_ad(req, AAD_LEN);
	aead_request_set_tfm(req, crypto->tfm);
	aead_request_set_callback(req, 0, crypto_req_done, &wait);

	aead_request_set_crypt(req, src, dst, len, crypto->iv);
	ret = crypto_wait_req(enc ? crypto_aead_encrypt(req) : crypto_aead_decrypt(req), &wait);

	aead_request_free(req);
	return ret;
}

static int encrypt_payload(struct snp_guest_dev *snp_dev, struct snp_guest_msg *msg,
			   void *plaintext, size_t len)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	struct snp_guest_msg_hdr *hdr = &msg->hdr;

	memset(crypto->iv, 0, crypto->iv_len);
	memcpy(crypto->iv, &hdr->msg_seqno, sizeof(hdr->msg_seqno));

	return enc_dec_message(crypto, msg, plaintext, msg->payload, len, true);
}

static int decrypt_payload(struct snp_guest_dev *snp_dev, struct snp_guest_msg *msg,
			   void *plaintext, size_t len)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	struct snp_guest_msg_hdr *hdr = &msg->hdr;

	/* Build IV with response buffer sequence number */
	memset(crypto->iv, 0, crypto->iv_len);
	memcpy(crypto->iv, &hdr->msg_seqno, sizeof(hdr->msg_seqno));

	return enc_dec_message(crypto, msg, msg->payload, plaintext, len, false);
}

static int __handle_guest_request(struct snp_guest_dev *snp_dev, int msg_type,
				 struct snp_user_guest_request *input, uint8_t *req_buf,
				 size_t req_sz, uint8_t *resp_buf, size_t resp_sz, size_t *msg_sz)
{
	struct snp_guest_msg *response = snp_dev->response;
	struct snp_guest_msg_hdr *resp_hdr = &response->hdr;
	struct snp_guest_msg *request = snp_dev->request;
	struct snp_guest_msg_hdr *req_hdr = &request->hdr;
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	struct snp_guest_request_data data;
	int ret;

	memset(request, 0, sizeof(*request));

	/* Populate the request header */
	req_hdr->algo = SNP_AEAD_AES_256_GCM;
	req_hdr->hdr_version = MSG_HDR_VER;
	req_hdr->hdr_sz = sizeof(*req_hdr);
	req_hdr->msg_type = msg_type;
	req_hdr->msg_version = input->msg_version;
	req_hdr->msg_seqno = snp_msg_seqno();
	req_hdr->msg_vmpck = 0;
	req_hdr->msg_sz = req_sz;

	dev_dbg(snp_dev->dev, "request [seqno %lld type %d version %d sz %d]\n",
		req_hdr->msg_seqno, req_hdr->msg_type, req_hdr->msg_version, req_hdr->msg_sz);

	/* Encrypt the request message buffer */
	ret = encrypt_payload(snp_dev, request, req_buf, req_sz);
	if (ret)
		return ret;

	/* Call firmware to process the request */
	data.req_gpa = __pa(request);
	data.resp_gpa = __pa(response);
	ret = snp_issue_guest_request(GUEST_REQUEST, &data);
	input->fw_err = ret;
	if (ret)
		return ret;

	dev_dbg(snp_dev->dev, "response [msg_seqno %lld msg_type %d msg_version %d msg_sz %d]\n",
		resp_hdr->msg_seqno, resp_hdr->msg_type, resp_hdr->msg_version, resp_hdr->msg_sz);

	/* Verify that the sequence counter is incremented by 1 */
	if (unlikely(resp_hdr->msg_seqno != (req_hdr->msg_seqno + 1)))
		return -EBADMSG;

	/* Verify response message type and version */
	if ((resp_hdr->msg_type != (req_hdr->msg_type + 1)) ||
	    (resp_hdr->msg_version != req_hdr->msg_version))
		return -EBADMSG;

	/*
	 * If the message size is greather than our buffer length then return
	 * an error.
	 */
	if (unlikely((resp_hdr->msg_sz + crypto->a_len) > resp_sz))
		return -EBADMSG;

	/* Decrypt the payload */
	ret = decrypt_payload(snp_dev, response, resp_buf, resp_hdr->msg_sz + crypto->a_len);
	if (ret)
		return ret;

	*msg_sz = resp_hdr->msg_sz;
	return 0;
}

static int handle_guest_request(struct snp_guest_dev *snp_dev, int msg_type,
				struct snp_user_guest_request *input, void *req_buf,
				size_t req_len, void __user *resp_buf, size_t resp_len)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	struct page *page;
	size_t msg_len;
	int ret;

	/* Allocate the buffer to hold response */
	resp_len += crypto->a_len;
	page = alloc_pages(GFP_KERNEL_ACCOUNT, get_order(resp_len));
	if (!page)
		return -ENOMEM;

	ret = __handle_guest_request(snp_dev, msg_type, input, req_buf, req_len,
			page_address(page), resp_len, &msg_len);
	if (ret)
		goto e_free;

	if (copy_to_user(resp_buf, page_address(page), msg_len))
		ret = -EFAULT;

e_free:
	__free_pages(page, get_order(resp_len));

	return ret;
}

static int get_report(struct snp_guest_dev *snp_dev, struct snp_user_guest_request *input)
{
	struct snp_user_report __user *report = (struct snp_user_report *)input->data;
	struct snp_user_report_req req;

	if (copy_from_user(&req, &report->req, sizeof(req)))
		return -EFAULT;

	return handle_guest_request(snp_dev, SNP_MSG_REPORT_REQ, input, &req.user_data,
			sizeof(req.user_data), report->response, sizeof(report->response));
}

static int derive_key(struct snp_guest_dev *snp_dev, struct snp_user_guest_request *input)
{
	struct snp_user_derive_key __user *key = (struct snp_user_derive_key *)input->data;
	struct snp_user_derive_key_req req;

	if (copy_from_user(&req, &key->req, sizeof(req)))
		return -EFAULT;

	return handle_guest_request(snp_dev, SNP_MSG_KEY_REQ, input, &req, sizeof(req),
			key->response, sizeof(key->response));
}

static long snp_guest_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	struct snp_guest_dev *snp_dev = to_snp_dev(file);
	struct snp_user_guest_request input;
	void __user *argp = (void __user *)arg;
	int ret = -ENOTTY;

	if (copy_from_user(&input, argp, sizeof(input)))
		return -EFAULT;

	mutex_lock(&snp_cmd_mutex);
	switch (ioctl) {
	case SNP_GET_REPORT: {
		ret = get_report(snp_dev, &input);
		break;
	}
	case SNP_DERIVE_KEY: {
		ret = derive_key(snp_dev, &input);
		break;
	}
	default:
		break;
	}

	mutex_unlock(&snp_cmd_mutex);

	if (copy_to_user(argp, &input, sizeof(input)))
		return -EFAULT;

	return ret;
}

static void free_shared_pages(void *buf, size_t sz)
{
	unsigned int npages = PAGE_ALIGN(sz) >> PAGE_SHIFT;

	/* If fail to restore the encryption mask then leak it. */
	if (set_memory_encrypted((unsigned long)buf, npages))
		return;

	__free_pages(virt_to_page(buf), get_order(sz));
}

static void *alloc_shared_pages(size_t sz)
{
	unsigned int npages = PAGE_ALIGN(sz) >> PAGE_SHIFT;
	struct page *page;
	int ret;

	page = alloc_pages(GFP_KERNEL_ACCOUNT, get_order(sz));
	if (IS_ERR(page))
		return NULL;

	ret = set_memory_decrypted((unsigned long)page_address(page), npages);
	if (ret) {
		__free_pages(page, get_order(sz));
		return NULL;
	}

	return page_address(page);
}

static const struct file_operations snp_guest_fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl = snp_guest_ioctl,
};

static int __init snp_guest_probe(struct platform_device *pdev)
{
	struct snp_secrets_page_layout *secrets;
	struct device *dev = &pdev->dev;
	struct snp_guest_dev *snp_dev;
	uint8_t key[VMPCK_KEY_LEN];
	struct miscdevice *misc;
	struct resource *res;
	void __iomem *base;
	int ret;

	snp_dev = devm_kzalloc(&pdev->dev, sizeof(struct snp_guest_dev), GFP_KERNEL);
	if (!snp_dev)
		return -ENOMEM;

	platform_set_drvdata(pdev, snp_dev);
	snp_dev->dev = dev;

	res = platform_get_mem_or_io(pdev, 0);
	if (IS_ERR(res))
		return PTR_ERR(res);

	/* Map the secrets page to get the key */
	base = ioremap_encrypted(res->start, resource_size(res));
	if (IS_ERR(base))
		return PTR_ERR(base);

	secrets = (struct snp_secrets_page_layout *)base;
	memcpy_fromio(key, secrets->vmpck0, sizeof(key));
	iounmap(base);

	snp_dev->crypto = init_crypto(snp_dev, key, sizeof(key));
	if (!snp_dev->crypto)
		return -EIO;

	/* Allocate the shared page used for the request and response message. */
	snp_dev->request = alloc_shared_pages(sizeof(struct snp_guest_msg));
	if (IS_ERR(snp_dev->request))
		return PTR_ERR(snp_dev->request);

	snp_dev->response = alloc_shared_pages(sizeof(struct snp_guest_msg));
	if (IS_ERR(snp_dev->response)) {
		ret = PTR_ERR(snp_dev->response);
		goto e_free_req;
	}

	misc = &snp_dev->misc;
	misc->minor = MISC_DYNAMIC_MINOR;
	misc->name = DEVICE_NAME;
	misc->fops = &snp_guest_fops;

	return misc_register(misc);

e_free_req:
	free_shared_pages(snp_dev->request, sizeof(struct snp_guest_msg));
	return ret;
}

static int __exit snp_guest_remove(struct platform_device *pdev)
{
	struct snp_guest_dev *snp_dev = platform_get_drvdata(pdev);

	free_shared_pages(snp_dev->request, sizeof(struct snp_guest_msg));
	free_shared_pages(snp_dev->response, sizeof(struct snp_guest_msg));
	deinit_crypto(snp_dev->crypto);
	misc_deregister(&snp_dev->misc);

	return 0;
}

static struct platform_driver snp_guest_driver = {
	.remove		= __exit_p(snp_guest_remove),
	.driver		= {
		.name = "snp-guest",
	},
};

module_platform_driver_probe(snp_guest_driver, snp_guest_probe);

MODULE_AUTHOR("Brijesh Singh <brijesh.singh@amd.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("AMD SNP Guest Driver");
