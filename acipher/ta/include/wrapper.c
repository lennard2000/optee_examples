#include <wrapper.h>
#include <crypto_values.h>
#include <tee_internal_api.h>

struct optee_operation_context {
    uint32_t algo;
    uint32_t type;
    uint32_t mode;
    uint32_t key_size;
    TEE_OperationHandle op_handle;
    TEE_ObjectHandle key_handle;
};

struct optee_operation_context *sessionctx;


psa_status_t psa_crypto_init(void) {
    return PSA_SUCCESS;
}

psa_status_t psa_hash_setup(
    TEE_OperationHandle *operation,
    psa_algorithm_t alg) {
    uint32_t teeAlgo;
    psa_status_t res;
    res = psa_alg_to_tee_alg(alg, &teeAlgo);
    if (res != PSA_SUCCESS) {
        IMSG("Algo not supported\n");
        return PSA_ERROR_NOT_SUPPORTED;
    }
    sessionctx->algo = teeAlgo;
    sessionctx->op_handle = *operation;
    sessionctx->mode = TEE_MODE_DIGEST;
    IMSG("assigned op to struc");
    TEE_AllocateOperation(&sessionctx->op_handle, sessionctx->algo, sessionctx->mode, 256);
    IMSG("allocated op");
    return PSA_SUCCESS;
}

psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length) {
    IMSG("started");

    uint32_t teeAlgo;
    IMSG("defined teeAlgo");

    psa_status_t algoStatus = psa_alg_to_tee_alg(alg, &teeAlgo);
    IMSG("executed mapping");

    if (algoStatus != PSA_SUCCESS) {
        IMSG("Algo not supported\n");
        return PSA_ERROR_NOT_SUPPORTED;
    }


    TEE_Result res;
    sessionctx->algo = teeAlgo;
    sessionctx->mode = TEE_MODE_DIGEST;

    res = TEE_AllocateOperation(&sessionctx->op_handle, sessionctx->algo, sessionctx->mode, 0);
    if (res != TEE_SUCCESS) {
        IMSG("tee allocation failed\n");
        return PSA_ERROR_GENERIC_ERROR;
    }

    res = TEE_DigestDoFinal(sessionctx->op_handle, input, input_length, hash, &hash_size);
    TEE_FreeOperation(sessionctx->op_handle);
    if (res != TEE_SUCCESS) {
        IMSG("Optee digest failed\n");
        return PSA_ERROR_GENERIC_ERROR;
    }

    *hash_length = hash_size;
    return PSA_SUCCESS;
}

psa_status_t psa_hash_update(TEE_OperationHandle __unused *operationHandle, const uint8_t *input,
                             size_t input_length) {
    TEE_DigestUpdate(sessionctx->op_handle, input, input_length);
    IMSG("updated hash input");
    return PSA_SUCCESS;
}

psa_status_t psa_hash_finish(TEE_OperationHandle __unused *operationHandle, uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length) {
    TEE_DigestDoFinal(sessionctx->op_handle, "", 0, hash, &hash_size);
    IMSG("processed do on final");
    *hash_length = hash_size;
    TEE_FreeOperation(sessionctx->op_handle);
    return PSA_SUCCESS;
}

TEE_Result psa_alg_to_tee_alg(psa_algorithm_t alg, uint32_t *teeAlgo) {
    switch (alg) {
        case PSA_ALG_MD5:
            *teeAlgo = TEE_ALG_MD5;
            break;
        case PSA_ALG_SHA_1:
            *teeAlgo = TEE_ALG_SHA1;
            break;
        case PSA_ALG_SHA_224:
            *teeAlgo = TEE_ALG_SHA224;
            break;
        case PSA_ALG_SHA_256:
            *teeAlgo = TEE_ALG_SHA256;
            break;
        case PSA_ALG_SHA_384:
            *teeAlgo = TEE_ALG_SHA384;
            break;
        case PSA_ALG_SHA_512:
            *teeAlgo = TEE_ALG_SHA512;
            break;
        case PSA_ALG_SHA3_224:
            *teeAlgo = TEE_ALG_SHA3_224;
            break;
        case PSA_ALG_SHA3_256:
            *teeAlgo = TEE_ALG_SHA3_256;
            break;
        case PSA_ALG_SHA3_384:
            *teeAlgo = TEE_ALG_SHA3_384;
            break;
        case PSA_ALG_SHA3_512:
            *teeAlgo = TEE_ALG_SHA3_512;
            break;
        case PSA_ALG_CBC_NO_PADDING:
            *teeAlgo = TEE_ALG_AES_CBC_NOPAD;
            break;
        case PSA_ALG_CTR:
            *teeAlgo = TEE_ALG_AES_CTR;
            break;
        case PSA_ALG_CBC_PKCS7:
            *teeAlgo = TEE_ALG_AES_CTR;
            break;


        //            TEE_ALG_AES_ECB_NOPAD
        //             TEE_ALG_AES_ECB_NOPAD
        //             TEE_ALG_AES_CBC_NOPAD
        //             TEE_ALG_AES_CTS
        //             TEE_ALG_AES_GCM
        //             TEE_ALG_AES_CMAC
        //             TEE_ALG_AES_CMAC
        //             TEE_ALG_HMAC_MD5
        //             TEE_ALG_HMAC_SHA1
        //             TEE_ALG_HMAC_SHA224
        //             TEE_ALG_HMAC_SHA256
        //             TEE_ALG_HMAC_SHA384
        //             TEE_ALG_HMAC_SHA512
        //             TEE_ALG_HMAC_MD5
        //            TEE_ALG_HMAC_SHA1
        //             TEE_ALG_HMAC_SHA224
        //             TEE_ALG_HMAC_SHA256
        //             TEE_ALG_HMAC_SHA384
        //             TEE_ALG_HMAC_SHA512


        default:
            IMSG("Algo not present\n");
            return TEE_ERROR_NOT_IMPLEMENTED;
    }
    return TEE_SUCCESS;
}

TEE_Result get_object_type_from_algo(uint32_t teeAlgo, uint32_t *tee_type) {
    switch (teeAlgo) {
        case TEE_ALG_AES_ECB_NOPAD:
        case TEE_ALG_AES_CBC_NOPAD:
        case TEE_ALG_AES_CTR:
        case TEE_ALG_AES_CTS:
        case TEE_ALG_AES_XTS:
        case TEE_ALG_AES_CCM:
        case TEE_ALG_AES_GCM:
        case TEE_ALG_AES_CBC_MAC_NOPAD:
        case TEE_ALG_AES_CBC_MAC_PKCS5:
        case TEE_ALG_AES_CMAC:
            *tee_type = TEE_TYPE_AES;
            break;
        case TEE_ALG_DES_ECB_NOPAD:
        case TEE_ALG_DES_CBC_NOPAD:
        case TEE_ALG_DES_CBC_MAC_NOPAD:
        case TEE_ALG_DES_CBC_MAC_PKCS5:
            *tee_type = TEE_TYPE_DES;
            break;
        case TEE_ALG_DES3_ECB_NOPAD:
        case TEE_ALG_DES3_CBC_NOPAD:
        case TEE_ALG_DES3_CBC_MAC_NOPAD:
        case TEE_ALG_DES3_CBC_MAC_PKCS5:
            *tee_type = TEE_TYPE_DES3;
            break;

        case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
        case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
        case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
        case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
        case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
        case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
        case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
        case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
        case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
        case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
        case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
            *tee_type = TEE_TYPE_RSA_KEYPAIR;
            break;
        case TEE_ALG_SHA256:
            *tee_type = TEE_TYPE_HMAC_SHA256;
            break;
        default:
            *tee_type = TEE_TYPE_AES;
            return TEE_ERROR_NOT_IMPLEMENTED;
    }
    return TEE_SUCCESS;
}

TEE_Result verify_key_size_by_type(uint32_t tee_type, int *key_size) {
    bool overwrite_key_size = false;
    int newValue;
    if (key_size == NULL || *key_size == 0) {
        overwrite_key_size = true;
    }
    switch (tee_type) {
        case TEE_TYPE_AES:
            if (*key_size == 128 || *key_size == 192 || *key_size == 256) {
                return TEE_SUCCESS;
            }
            if (overwrite_key_size) {
                newValue = 256;
            }
            break;
        case TEE_TYPE_RSA_KEYPAIR:
            if (*key_size == 256 || *key_size == 512 || *key_size == 768 || *key_size == 1024 || *key_size == 1536 ||
                *key_size == 2048) {
                return TEE_SUCCESS;
            }
            if (overwrite_key_size) {
                newValue = 2048;
            }
            break;
        case TEE_TYPE_DES3:
            if (*key_size == 128 || *key_size == 192) {
                return TEE_SUCCESS;
            }
            if (overwrite_key_size) {
                newValue = 192;
            }
            break;
        case TEE_TYPE_DES:
            if (*key_size == 64)
                return TEE_SUCCESS;
            if (overwrite_key_size) newValue = 64;
    }
    if (overwrite_key_size) {
        *key_size = newValue;
        return TEE_ERROR_BAD_PARAMETERS;
    }
    IMSG("%d", overwrite_key_size);
    return TEE_ERROR_NOT_IMPLEMENTED;
}

psa_status_t psa_generate_random(void *buffer, size_t bufferSize) {
    IMSG("entered random");
    TEE_GenerateRandom(buffer, bufferSize);
    return PSA_SUCCESS;
}

psa_status_t psa_generate_key(int key_bits, psa_algorithm_t psaAlgorithm,
                              TEE_ObjectHandle *key) {
    uint32_t tee_algo;
    uint32_t tee_type;
    TEE_Result status = psa_alg_to_tee_alg(psaAlgorithm, &tee_algo);
    TEE_FreeTransientObject(sessionctx->key_handle);
    sessionctx->key_handle = TEE_HANDLE_NULL;

    if (status != TEE_SUCCESS) {
        IMSG("Algo not present\n");
    }
    status = get_object_type_from_algo(tee_algo, &tee_type);

    if (status != TEE_SUCCESS) {
        //error catching here
    }
    status = verify_key_size_by_type(tee_type, &key_bits);
    if (status != TEE_SUCCESS || status != TEE_ERROR_BAD_PARAMETERS) {
        IMSG("wrong key bits %d", key_bits);
    }
    sessionctx->key_size = key_bits;
    status = TEE_AllocateTransientObject(tee_type, sessionctx->key_size, &sessionctx->key_handle);

    if (status != TEE_SUCCESS) {
        IMSG("allocate failed \n");
    }
    status = TEE_GenerateKey(sessionctx->key_handle, sessionctx->key_size, NULL, 0);
    if (status != TEE_SUCCESS) {
        IMSG("failed to generate key");
        //        error handling here
    }
    return PSA_SUCCESS;
}


psa_status_t psa_cipher_setup(TEE_OperationHandle
                              *__unused operationHandle,
                              TEE_ObjectHandle *key, psa_algorithm_t
                              psaAlgorithm,
                              char *iv,
                              size_t
                              iv_size, uint32_t mode) {
    TEE_Result result;


    uint32_t tee_alg;
    psa_status_t res;
    res = psa_alg_to_tee_alg(psaAlgorithm, &tee_alg);
    if (res != PSA_SUCCESS) {
        IMSG("algo failed \n");
    }

    sessionctx->algo = tee_alg;
    sessionctx->mode = mode;

    if (sessionctx->op_handle != TEE_HANDLE_NULL) {
        IMSG("op was not null");
        TEE_ResetOperation(sessionctx->op_handle);
    }

    IMSG("started Allocation");
    result = TEE_AllocateOperation(&sessionctx->op_handle,
                                   sessionctx->algo,
                                   sessionctx->mode,
                                   sessionctx->key_size);
    if (result != TEE_SUCCESS) {
        IMSG("failed op");
    }
    IMSG("Allocation finished");

    TEE_Result res1 = TEE_SetOperationKey(sessionctx->op_handle, sessionctx->key_handle);
    if (res1 != TEE_SUCCESS) {
        IMSG("key setting failed");
    }
    IMSG("Key set");
    TEE_CipherInit(sessionctx->op_handle, iv, iv_size);
    IMSG("cipher innit \n");

    return PSA_SUCCESS;
}

psa_status_t psa_cipher_decrypt_setup(TEE_OperationHandle
                                      *operationHandle,
                                      TEE_ObjectHandle *key, psa_algorithm_t
                                      psaAlgorithm,
                                      char *iv,
                                      size_t iv_size) {
    return psa_cipher_setup(operationHandle, key, psaAlgorithm, iv, iv_size, TEE_MODE_DECRYPT);
}

psa_status_t psa_cipher_encrypt_setup(TEE_OperationHandle
                                      *operationHandle,
                                      TEE_ObjectHandle *key, psa_algorithm_t
                                      psaAlgorithm,
                                      char *iv,
                                      size_t iv_size) {
    return psa_cipher_setup(operationHandle, key, psaAlgorithm, iv, iv_size, TEE_MODE_ENCRYPT);
}

psa_status_t psa_cipher_update(TEE_OperationHandle
                               *operationHandle, const uint8_t *input, size_t input_size,
                               uint8_t *output, size_t output_size, size_t* output_len) {
    if (sessionctx->op_handle == TEE_HANDLE_NULL) {
        IMSG("OP not defined");
    }
    TEE_Result result = TEE_CipherUpdate(sessionctx->op_handle, input, input_size, output, &output_size);
    if (result == TEE_ERROR_SHORT_BUFFER)
    {
        IMSG("Buffer too short");
    }
    if (result != TEE_SUCCESS) {
        IMSG("Error updating cipher %d", result);
        return PSA_ERROR_BAD_STATE;
    }
    *output_len = output_size;
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_finish(TEE_OperationHandle
                               *operationHandle,
                               uint8_t *output, size_t output_size, size_t output_len) {
    if (sessionctx->op_handle == TEE_HANDLE_NULL) {
        IMSG("OP not defined");
    }
    TEE_Result res = TEE_CipherDoFinal(sessionctx->op_handle, "", 0, output, &output_size);
    if (res != TEE_SUCCESS) {
        IMSG("Operation failed");
        IMSG("error type: %u", res);
    }
    IMSG("Operation finished, clearing operation");
    TEE_FreeOperation(sessionctx->op_handle);
    sessionctx->op_handle = TEE_HANDLE_NULL;
    return PSA_SUCCESS;
}


psa_status_t create_session(void *session) {
    struct optee_operation_context *sess;

    /*
     * Allocate and init ciphering materials for the session.
     * The address of the structure is used as session ID for
     * the client.
     */
    sess = TEE_Malloc(sizeof(*sess), 0);
    if (!sess)
        return PSA_ERROR_NOT_SUPPORTED;

    sess->key_handle = TEE_HANDLE_NULL;
    sess->op_handle = TEE_HANDLE_NULL;
    sessionctx = sess;
    session = (void *) sess;
    return PSA_SUCCESS;
}

void mbedtls_psa_crypto_free() {
}

psa_status_t psa_mac_sign_setup(TEE_OperationHandle *operation,
                                psa_algorithm_t alg, TEE_ObjectHandle *key) {
    uint32_t teeAlgo;
    psa_status_t res;
    res = psa_alg_to_tee_alg(alg, &teeAlgo);
    if (res != PSA_SUCCESS) {
        IMSG("Algo not supported\n");
        return PSA_ERROR_NOT_SUPPORTED;
    }
    sessionctx->algo = teeAlgo;
    sessionctx->op_handle = *operation;
    sessionctx->mode = TEE_MODE_DIGEST;
    IMSG("assigned op to struc");
    TEE_AllocateOperation(&sessionctx->op_handle, sessionctx->algo, sessionctx->mode, sessionctx->key_size);
    IMSG("allocated op");
    return PSA_SUCCESS;
}

psa_status_t psa_mac_update(TEE_OperationHandle *operation, const void *chunk,
                            size_t chunkSize) {
     TEE_MACUpdate(&sessionctx->op_handle, chunk, chunkSize);

    return PSA_SUCCESS;
}
psa_status_t psa_mac_sign_finish(TEE_OperationHandle *operation,void *mac, size_t macLen, size_t* macSize) {
    psa_status_t res;
    res =  TEE_MACComputeFinal(sessionctx->op_handle,"", 0, mac, &macLen);
    TEE_FreeOperation(sessionctx->op_handle);
    if (res != TEE_SUCCESS) {
        IMSG("mac sign failed\n");
        return PSA_ERROR_GENERIC_ERROR;
    }
    *macSize = macSize;

    return PSA_SUCCESS;
}
