// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */
/*
The code for this example is copied from programs/psa/crypto_examples.c from https://github.com/Mbed-TLS/TF-PSA-Crypto/
 */
#include <mbedtls/build_info.h>  // Mbed TLS 3.x config/adjust chain
#include <psa/build_info.h>      // PSA config chosen by your core export
#include "mbedtls/mbedtls_config.h"
#include <mbedtls/cipher.h>
#include <psa/crypto.h>

#include <psa/crypto_types.h>
#include <psa/crypto_values.h>
#include <psa/crypto_extra.h>

#include <tee_internal_api.h>
#include <string.h>
#include <acipher_ta.h>
#include <trace.h>

#define ASSERT(predicate)                                                   \
    do                                                                        \
    {                                                                         \
        if (!(predicate))                                                 \
        {                                                                     \
            IMSG("\tassertion failed at %s:%d - '%s'\r\n",         \
                   __FILE__, __LINE__, #predicate);                  \
            TEE_Panic(0xdeadbeef);                                                        \
        }                                                                     \
    } while (0)

#define ASSERT_STATUS(actual, expected)                                     \
    do                                                                        \
    {                                                                         \
        if ((actual) != (expected))                                      \
        {                                                                     \
            IMSG("\tassertion failed at %s:%d - "                  \
                   "actual:%d expected:%d\r\n", __FILE__, __LINE__,  \
                   (psa_status_t) actual, (psa_status_t) expected); \
            TEE_Panic(0xdeadbeef);                                                        \
        }                                                                     \
    } while (0)

#define string4 "12345678"

TEE_Result TA_CreateEntryPoint(void) {
    IMSG("TA sizeof(psa_cipher_operation_t)=%zu", sizeof(psa_cipher_operation_t));
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {


    return TEE_SUCCESS;
}
void TA_CloseSessionEntryPoint(void *sess_ctx) {
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
                          input_size - bytes_written);
        IMSG("write bytes");

        status = psa_cipher_update(operation, input + bytes_written,
                                   bytes_to_write, output + *output_len,
                                   output_size - *output_len, &len);
        IMSG("Total out_len = %zu (cap = %zu)", output_size - *output_len, len);
        IMSG("cipher update");
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
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    size_t iv_len = 0;

    memset(&operation, 0, sizeof(operation));
    status = psa_cipher_encrypt_setup(&operation, key, alg);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_cipher_generate_iv(&operation, iv, iv_size, &iv_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_operation(&operation, input, input_size, part_size,
                              output, output_size, output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    psa_cipher_abort(&operation);
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
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

     memset(&operation, 0, sizeof(operation));
    status = psa_cipher_decrypt_setup(&operation, key, alg);
    IMSG("decrypt setup");
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_cipher_set_iv(&operation, iv, iv_size);
    IMSG("cipher_decrypt_iv");
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_operation(&operation, input, input_size, part_size,
                              output, output_size, output_len);
    IMSG("cipher_operation");
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    psa_cipher_abort(&operation);
    IMSG("aborted");
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

    status = psa_generate_random(input, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_bits);

    status = psa_generate_key(&attributes, &key);
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
    psa_destroy_key(key);
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

    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_bits);

    status = psa_generate_key(&attributes, &key);
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
    psa_destroy_key(key);
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
    ASSERT_STATUS(status, PSA_SUCCESS);

    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_bits);

    status = psa_generate_key(&attributes, &key);
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
    psa_destroy_key(key);
    return status;
}

static void cipher_examples(void)
{
    psa_status_t status;
    psa_status_t st = psa_crypto_init();
    ASSERT_STATUS(st, PSA_SUCCESS);
    IMSG("cipher encrypt/decrypt AES CBC no padding:\r\n");
    status = cipher_example_encrypt_decrypt_aes_cbc_nopad_1_block();
    if (status == PSA_SUCCESS) {
        IMSG("\tsuccess!\r\n");
    }

    IMSG("cipher encrypt/decrypt AES CBC PKCS7 multipart:\r\n");
    status = cipher_example_encrypt_decrypt_aes_cbc_pkcs7_multi();
    if (status == PSA_SUCCESS) {
        IMSG("\tsuccess!\r\n");
    }

    IMSG("cipher encrypt/decrypt AES CTR multipart:\r\n");
    status = cipher_example_encrypt_decrypt_aes_ctr_multi();
    if (status == PSA_SUCCESS) {
        IMSG("\tsuccess!\r\n");
    }
}
TEE_Result TA_InvokeCommandEntryPoint(void *session_id,
                                      uint32_t command_id,
                                      uint32_t parameters_type,
                                      TEE_Param parameters[4]) {
    psa_status_t st = psa_crypto_init();
    ASSERT_STATUS(st, PSA_SUCCESS);
    cipher_examples();
    return TEE_SUCCESS;

}
