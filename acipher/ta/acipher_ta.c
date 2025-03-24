// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */
/*
The code for this example is copied from programs/psa/crypto_examples.c from https://github.com/Mbed-TLS/TF-PSA-Crypto/
 */

#include <tee_internal_api.h>
#include <string.h>
#include <include/crypto_types.h>
#include <acipher_ta.h>
#include <include/wrapper.h>
#include <include/wrapper.c>
#include <include/crypto_struct.h>

static TEE_Result cmd_gen_key(struct acipher *state, uint32_t pt,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	uint32_t key_size;
	TEE_ObjectHandle key;
	const uint32_t key_type = TEE_TYPE_RSA_KEYPAIR;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

#define ASSERT(predicate)                                                   \
    do                                                                        \
    {                                                                         \
        if (!(predicate))                                                 \
        {                                                                     \
            printf("\tassertion failed at %s:%d - '%s'\r\n",         \
                   __FILE__, __LINE__, #predicate);                  \
            goto exit;                                                        \
        }                                                                     \
    } while (0)

#define ASSERT_STATUS(actual, expected)                                     \
    do                                                                        \
    {                                                                         \
        if ((actual) != (expected))                                      \
        {                                                                     \
            printf("\tassertion failed at %s:%d - "                  \
                   "actual:%d expected:%d\r\n", __FILE__, __LINE__,  \
                   (psa_status_t) actual, (psa_status_t) expected); \
            goto exit;                                                        \
        }                                                                     \
    } while (0)

#define string4 "12345678"

	res = TEE_GenerateKey(key, key_size, NULL, 0);
	if (res) {
		EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32,
		     key_size, res);
		TEE_FreeTransientObject(key);
		return res;
	}

	TEE_FreeTransientObject(state->key);
	state->key = key;
	return TEE_SUCCESS;
}

static TEE_Result cmd_enc(struct acipher *state, uint32_t pt,
			  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	const void *inbuf;
	uint32_t inbuf_len;
	void *outbuf;
	uint32_t outbuf_len;
	TEE_OperationHandle op;
	TEE_ObjectInfo key_info;
	const uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!state->key)
		return TEE_ERROR_BAD_STATE;

	res = TEE_GetObjectInfo1(state->key, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
		return res;
	}

	inbuf = params[0].memref.buffer;
	inbuf_len = params[0].memref.size;
	outbuf = params[1].memref.buffer;
	outbuf_len = params[1].memref.size;

	res = TEE_AllocateOperation(&op, alg, TEE_MODE_ENCRYPT,
				    key_info.keySize);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_ENCRYPT, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, alg, key_info.keySize, res);
		return res;
	}

	res = TEE_SetOperationKey(op, state->key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}

	res = TEE_AsymmetricEncrypt(op, NULL, 0, inbuf, inbuf_len, outbuf,
				    &outbuf_len);
	if (res) {
		EMSG("TEE_AsymmetricEncrypt(%" PRId32 ", %" PRId32 "): %#" PRIx32, inbuf_len, params[1].memref.size, res);
	}
	params[1].memref.size = outbuf_len;

out:
	TEE_FreeOperation(op);
	return res;

}

TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}



static psa_status_t cipher_operation(psa_cipher_operation_t *operation,
                                     const uint8_t *input,
                                     size_t input_size,
                                     size_t part_size,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_len)
{
    psa_status_t status;
    size_t bytes_to_write = 0, bytes_written = 0, len = 0;
    *output_len = 0;
    while (bytes_written != input_size) {
        bytes_to_write = (input_size - bytes_written > part_size ?
                          part_size :
                          input_size - bytes_written -1);

        status = psa_cipher_update(operation, input + bytes_written,
                                   bytes_to_write, output + *output_len,
                                   output_size - *output_len, &len);
        ASSERT_STATUS(status, PSA_SUCCESS);
        bytes_written += bytes_to_write;
        *output_len += len;
    }

    status = psa_cipher_finish(operation, output + *output_len,
                               output_size - *output_len, &len);
    ASSERT_STATUS(status, PSA_SUCCESS);
    *output_len += len;

exit:
    return status;
}

static psa_status_t cipher_encrypt(psa_key_id_t key,
                                   psa_algorithm_t alg,
                                   uint8_t *iv,
                                   size_t iv_size,
                                   const uint8_t *input,
                                   size_t input_size,
                                   size_t part_size,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_len)
{
    psa_status_t status;
    psa_cipher_operation_t* operation;
    size_t iv_len = 0;

    // memset(&operation, 0, sizeof(operation));
    // this call is different, since we cant really save data on the psa_cipher_operation_t
    status = psa_cipher_encrypt_setup(operation, key, alg, iv, iv_size);
    ASSERT_STATUS(status, PSA_SUCCESS);

    // status = psa_cipher_generate_iv(&operation, iv, iv_size, &iv_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_operation(&operation, input, input_size, part_size,
                              output, output_size, output_len);
    printf("cipher_encrypt");
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    // psa_cipher_abort(&operation);
    return status;
}

static psa_status_t cipher_decrypt(psa_key_id_t key,
                                   psa_algorithm_t alg,
                                   const uint8_t *iv,
                                   size_t iv_size,
                                   const uint8_t *input,
                                   size_t input_size,
                                   size_t part_size,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_len)
{
    psa_status_t status;
    // this line is changed, since we don't need to initialize the operation
    psa_cipher_operation_t* operation;

    // memset(&operation, 0, sizeof(operation));
    status = psa_cipher_decrypt_setup(operation, key, alg, iv, iv_size);
    ASSERT_STATUS(status, PSA_SUCCESS);

    // status = psa_cipher_set_iv(&operation, iv, iv_size);
    ASSERT_STATUS(status, PSA_SUCCESS);
    status = cipher_operation(&operation, input, input_size, part_size,
                              output, output_size, output_len);
    printf("cipher_decrypt");
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    // psa_cipher_abort(&operation);
    return status;
}

static psa_status_t
cipher_example_encrypt_decrypt_aes_cbc_nopad_1_block(void)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES),
        key_bits = 256,
        part_size = block_size,
    };
    const psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    size_t output_len = 0;
    uint8_t iv[block_size];
    uint8_t input[block_size];
    uint8_t encrypt[block_size];
    uint8_t decrypt[block_size];

    status = psa_generate_random(&input, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

    // we don't need these usage flags, since we simply pass the options directly to the optee function
    // psa_set_key_usage_flags(&attributes,
    //                         PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    // psa_set_key_algorithm(&attributes, alg);
    // psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    // psa_set_key_bits(&attributes, key_bits);

    // we derive the key type from used algo
    status = psa_generate_key(key_bits, alg, &key);
    ASSERT_STATUS(status, PSA_SUCCESS);
    printf(input);
    status = cipher_encrypt(key, alg, iv, sizeof(iv),
                            input, sizeof(input), part_size,
                            encrypt, sizeof(encrypt), &output_len);
    printf(encrypt);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_decrypt(key, alg, iv, sizeof(iv),
                            encrypt, output_len, part_size,
                            decrypt, sizeof(decrypt), &output_len);
    printf(decrypt);
    ASSERT_STATUS(status, PSA_SUCCESS);
    status = memcmp(input, decrypt, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    // psa_destroy_key(key);
    return status;
}

static psa_status_t cipher_example_encrypt_decrypt_aes_cbc_pkcs7_multi(void)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES),
        key_bits = 256,
        input_size = 100,
        part_size = 10,
    };

    const psa_algorithm_t alg = PSA_ALG_CBC_PKCS7;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    size_t output_len = 0;
    uint8_t iv[block_size], input[input_size],
            encrypt[input_size + block_size], decrypt[input_size + block_size];

    status = psa_generate_random(input, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);
    // same here
    // psa_set_key_usage_flags(&attributes,
    //                         PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    // psa_set_key_algorithm(&attributes, alg);
    // psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    // psa_set_key_bits(&attributes, key_bits);

    status = psa_generate_key(key_bits, alg, &key);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_encrypt(key, alg, iv, sizeof(iv),
                            input, sizeof(input), part_size,
                            encrypt, sizeof(encrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_decrypt(key, alg, iv, sizeof(iv),
                            encrypt, output_len, part_size,
                            decrypt, sizeof(decrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);
    status = memcmp(input, decrypt, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    // psa_destroy_key(key);
    return status;
}

static psa_status_t cipher_example_encrypt_decrypt_aes_ctr_multi(void)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES),
        key_bits = 256,
        input_size = 100,
        part_size = 10,
    };
    const psa_algorithm_t alg = PSA_ALG_CTR;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    size_t output_len = 0;
    uint8_t iv[block_size], input[input_size], encrypt[input_size],
            decrypt[input_size];

    status = psa_generate_random(input, sizeof(input));
    printf(input);
    ASSERT_STATUS(status, PSA_SUCCESS);

    // psa_set_key_usage_flags(&attributes,
    //                         PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    // psa_set_key_algorithm(&attributes, alg);
    // psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    // psa_set_key_bits(&attributes, key_bits);

    status = psa_generate_key(key_bits, alg, &key);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_encrypt(key, alg, iv, sizeof(iv),
                            input, sizeof(input), part_size,
                            encrypt, sizeof(encrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_decrypt(key, alg, iv, sizeof(iv),
                            encrypt, output_len, part_size,
                            decrypt, sizeof(decrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);
    printf(input);
    printf("\n");
    printf(decrypt);
    status = memcmp(input, decrypt, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    // psa_destroy_key(key);
    return status;
}

static void cipher_examples(void)
{
    psa_status_t status;

    printf("cipher encrypt/decrypt AES CBC no padding:\r\n");
    status = cipher_example_encrypt_decrypt_aes_cbc_nopad_1_block();
    printf("first part finished");
    if (status == PSA_SUCCESS) {
        printf("\tsuccess!\r\n");
    }

    printf("cipher encrypt/decrypt AES CBC PKCS7 multipart:\r\n");
    status = cipher_example_encrypt_decrypt_aes_cbc_pkcs7_multi();
    if (status == PSA_SUCCESS) {
        printf("\tsuccess!\r\n");
    }

    printf("cipher encrypt/decrypt AES CTR multipart:\r\n");
    status = cipher_example_encrypt_decrypt_aes_ctr_multi();
    if (status == PSA_SUCCESS) {
        printf("\tsuccess!\r\n");
    }
}
TEE_Result TA_InvokeCommandEntryPoint(void *session_id,
                                      uint32_t command_id,
                                      uint32_t parameters_type,
                                      TEE_Param parameters[4]) {
    cipher_examples();
    return TEE_SUCCESS;

}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case TA_ACIPHER_CMD_GEN_KEY:
		return cmd_gen_key(session, param_types, params);
	case TA_ACIPHER_CMD_ENCRYPT:
		return cmd_enc(session, param_types, params);
	default:
		EMSG("Command ID %#" PRIx32 " is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
