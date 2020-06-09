#include<inttypes.h>
#include<tee_internal_api.h>
#include<tee_internal_api_extensions.h>
#include<string.h>
#include<proxy_ta.h>
#include<mbedtls/ecdh.h>
#include<mbedtls/ecp.h>
#include<mbedtls/pk.h>
#include<mbedtls/x509_crt.h>
#include<mbedtls/md.h>


struct ke_session {
    mbedtls_ecdh_context *dh_ctx;
    TEE_ObjectHandle sh_key;     
};


static int f_rng(void *rng __unused, unsigned char *buf, size_t buf_s){
    TEE_GenerateRandom(buf, buf_s);

    return 0;
}


/*
 * Verifies the authenticity of the client parameters
 */
static TEE_Result verify_cli_params(TEE_Param params[4]){
    TEE_Result res = TEE_SUCCESS;
    mbedtls_x509_crt ca_crt;
    mbedtls_x509_crt client_crt;
    void *buf = TEE_Malloc(64, TEE_MALLOC_FILL_ZERO);
    uint32_t flags;

    mbedtls_x509_crt_init(&ca_crt);
    mbedtls_x509_crt_init(&client_crt);

    if(!buf){
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    res = mbedtls_x509_crt_parse_der(&ca_crt, ca_cert, sizeof(ca_cert));
    if(res){
        res = TEE_ERROR_SECURITY;
        goto error;
    }
    
    res = mbedtls_x509_crt_parse(&client_crt, params[2].memref.buffer, params[2].memref.size);
    if(res){
        res = TEE_ERROR_SECURITY;
        goto error;
    }

    res = mbedtls_x509_crt_verify(&client_crt, &ca_crt, NULL, NULL, &flags, NULL, NULL);
    if(res || flags){
        res = TEE_ERROR_SECURITY;
        goto error;
    }
        
    res = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                     params[1].memref.buffer, params[1].memref.size,
                     buf);
    if(res){
        res = TEE_ERROR_SECURITY;
        goto error;
    }

    res = mbedtls_pk_verify(&client_crt.pk, MBEDTLS_MD_SHA256,
                            buf, 64,
                            params[0].memref.buffer, params[0].memref.size);
    if(res)
        res = TEE_ERROR_SECURITY;

error:
    TEE_Free(buf);
    mbedtls_x509_crt_free(&ca_crt);
    mbedtls_x509_crt_free(&client_crt);
    return res;
}


/*
 * Receives the public DH params from the client and generates the shared secret
 */
static TEE_Result init_ke(void *s_ptr, uint32_t pt, TEE_Param params[4]){
    TEE_Result res = TEE_SUCCESS;
    TEE_OperationHandle md = TEE_HANDLE_NULL;
    TEE_Attribute attr[1];
    struct ke_session *sess = (struct ke_session*)s_ptr;
    void *tmp = NULL , *sh_key = NULL;
    size_t tmp_l;
    uint32_t sh_key_l, e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, // Signature
                                              TEE_PARAM_TYPE_MEMREF_INPUT, // DH Parameters
                                              TEE_PARAM_TYPE_MEMREF_INPUT, // Certificate
                                              TEE_PARAM_TYPE_NONE);

    if(e_pt != pt)
        return TEE_ERROR_BAD_PARAMETERS;

    res = verify_cli_params(params);
    if(res){
        res = TEE_ERROR_SECURITY;
        goto error;
    }

    res = mbedtls_ecdh_read_public(sess->dh_ctx, params[1].memref.buffer, params[1].memref.size);
    if(res){
        res = TEE_ERROR_SECURITY;
        goto error;
    }

    tmp = TEE_Malloc(32*sizeof(uint8_t), TEE_MALLOC_FILL_ZERO);
    if(!tmp){
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto error;
    }
    tmp_l = 32;

    res = mbedtls_ecdh_calc_secret(sess->dh_ctx, &tmp_l,
                                   tmp, tmp_l,
                                   f_rng, NULL);
    if(res)
        goto error;

    // Convert shared secret to AES key
    res = TEE_AllocateOperation(&md, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if(res)
        goto error;

    sh_key = TEE_Malloc(32*sizeof(uint8_t), TEE_MALLOC_FILL_ZERO);
    if(!sh_key){
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto error;
    }
    sh_key_l = 32;

    res = TEE_DigestDoFinal(md, tmp, tmp_l, sh_key, &sh_key_l);
    if(res)
        goto error;

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &sess->sh_key);
    if(res)
        goto error;

    TEE_InitRefAttribute(attr, TEE_ATTR_SECRET_VALUE, sh_key, sh_key_l);
    res = TEE_PopulateTransientObject(sess->sh_key, attr, 1);
    if(!res)
        goto out;

error:
    TEE_FreeTransientObject(sess->sh_key);
out:
    TEE_FreeOperation(md);
    TEE_Free(sh_key);
    TEE_Free(tmp);
    return res;
}

/*
 * Returns the device certificate corresponding to the key used in attestation
 */
static TEE_Result get_device_cert(void *s_ptr __unused, uint32_t pt, TEE_Param params[4]){
    TEE_Result res = TEE_SUCCESS;
	TEE_TASessionHandle sess;
	TEE_UUID au = ATTEST_PTA_UUID;
    uint32_t eo;
    uint32_t e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE);

    if(e_pt != pt)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_OpenTASession(&au, TEE_TIMEOUT_INFINITE, 0, NULL, &sess, &eo);
    if(!res){
        res = TEE_InvokeTACommand(sess,
                                  TEE_TIMEOUT_INFINITE,
                                  ATTEST_PTA_CMD_GET_CERT,
                                  pt, params,
                                  &eo);
        TEE_CloseTASession(sess);
    }

    return res;
}


/*
 * Encrypts a payload stored in buf and stores it in ctxt
 * ctxt: tag || iv || encrypted plain text
 */
static TEE_Result encrypt_payload(struct ke_session *sess, void *buf, uint32_t len, void *ctxt, uint32_t *ctxt_l){
    TEE_Result res = TEE_SUCCESS;
    TEE_OperationHandle enc_op = TEE_HANDLE_NULL;
    uint32_t tag_len = 16;

    res = TEE_AllocateOperation(&enc_op, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT, 256);
    if(res)
        goto out;

    res = TEE_SetOperationKey(enc_op, sess->sh_key);
    if(res)
        goto out;
    
    TEE_GenerateRandom((uint8_t *)ctxt + 16, 12);

    res = TEE_AEInit(enc_op, (uint8_t *)ctxt + 16, 12, 16*8, 0, 0);
    if(res)
        goto out;

    *ctxt_l = len;

    res = TEE_AEEncryptFinal(enc_op,
                             buf, len,
                             (uint8_t *)ctxt + 16 + 12, ctxt_l,
                             ctxt, &tag_len);

    *ctxt_l += tag_len + 12;

out:
    TEE_FreeOperation(enc_op);
    return res;
}


/*
 * Decrypts the payload stored in buf and stores it in ptxt
 * buf: tag || iv || encrypted plain text
 */
static TEE_Result decrypt_payload(struct ke_session *sess, void *buf, uint32_t len, void *ptxt, uint32_t *ptxt_l){
    TEE_Result res = TEE_SUCCESS;
    TEE_OperationHandle dec_op = TEE_HANDLE_NULL;

    res = TEE_AllocateOperation(&dec_op, TEE_ALG_AES_GCM, TEE_MODE_DECRYPT, 256);
    if(res)
        goto out;

    res = TEE_SetOperationKey(dec_op, sess->sh_key);
    if(res)
        goto out;

    res = TEE_AEInit(dec_op, (uint8_t *)buf + 16, 12, 16*8, 0, 0);
    if(res)
        goto out;

    res = TEE_AEDecryptFinal(dec_op,
                             (uint8_t *)buf + 16 + 12, len - 16 - 12,
                             ptxt, ptxt_l,
                             buf, 16);
out:
    TEE_FreeOperation(dec_op);
    return res;
}



static TEE_Result install_ta(void *s_ptr, uint32_t pt, TEE_Param params[4]){
    TEE_Result res = TEE_SUCCESS;
    struct ke_session *s_ke = (struct ke_session*)s_ptr;
    void *ta_bin = NULL, *tmp;
    uint32_t ta_size = 0;
    uint32_t e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,                       //TA Binary
                                    TEE_PARAM_TYPE_MEMREF_INPUT | TEE_PARAM_TYPE_NONE, //TA Certificate (optional)
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE);

    if((e_pt & pt) != pt)
        return TEE_ERROR_BAD_PARAMETERS;


    ta_bin = TEE_Malloc(MAX_TA_SIZE, TEE_MALLOC_FILL_ZERO);
    ta_size = MAX_TA_SIZE;
    if(!ta_bin)
        return TEE_ERROR_OUT_OF_MEMORY;

    res = decrypt_payload(s_ke, params[0].memref.buffer, params[0].memref.size, ta_bin, &ta_size);
    if(res)
        return res;

    if(ta_size < MAX_TA_SIZE){
        tmp = TEE_Realloc(ta_bin, ta_size);
        if(!tmp){
            TEE_Free(ta_bin);
            res = TEE_ERROR_OUT_OF_MEMORY;
        }else ta_bin = tmp;
    }

    TEE_Free(ta_bin);

    if(TEE_PARAM_TYPE_GET(pt, 1) == TEE_PARAM_TYPE_MEMREF_INPUT){
        ta_bin = TEE_Malloc(params[1].memref.size, TEE_MALLOC_FILL_ZERO);
        ta_size = params[1].memref.size;
        if(!ta_bin)
            return TEE_ERROR_OUT_OF_MEMORY;

        res = decrypt_payload(s_ke, params[1].memref.buffer, params[1].memref.size, ta_bin, &ta_size);
        if(res)
            return res;

        if(ta_size < MAX_TA_SIZE){
            tmp = TEE_Realloc(ta_bin, ta_size);
            if(!tmp){
                TEE_Free(ta_bin);
                res = TEE_ERROR_OUT_OF_MEMORY;
            }else ta_bin = tmp;
        }
        TEE_Free(ta_bin);
    }

    return res;
}

/*
 * Proxy between Client Application and other TA, decrypting and encrypting
 * the exchanged data and issuing the requested command
 */
static TEE_Result cmd_ta(void *s_ptr, uint32_t pt, TEE_Param params[4]){
    TEE_Result res;
    TEE_UUID ta_uuid;
    TEE_TASessionHandle sess;
    TEE_Param ta_params[1];
    void *tmp;
    struct ke_session *s_ke = (struct ke_session*)s_ptr;
    uint32_t eo, e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, //TA UUID
                                        TEE_PARAM_TYPE_VALUE_INPUT,  //Command ID
                                        TEE_PARAM_TYPE_MEMREF_INOUT, //Data
                                        TEE_PARAM_TYPE_NONE);

    if(e_pt != pt)
        return TEE_ERROR_BAD_PARAMETERS;

    tee_uuid_from_str(&ta_uuid, params[0].memref.buffer);

    pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                         TEE_PARAM_TYPE_NONE,
                         TEE_PARAM_TYPE_NONE,
                         TEE_PARAM_TYPE_NONE);

    ta_params[0].memref.size = params[2].memref.size;
    ta_params[0].memref.buffer = TEE_Malloc(params[2].memref.size, TEE_MALLOC_FILL_ZERO);
    if(!ta_params[0].memref.buffer)
        return TEE_ERROR_OUT_OF_MEMORY;

    res = decrypt_payload(s_ke,
                          params[2].memref.buffer, params[2].memref.size,
                          ta_params[0].memref.buffer, &ta_params[0].memref.size);
    if(res)
        return res;

    if(ta_params[0].memref.size < params[2].memref.size){
        tmp = TEE_Realloc(ta_params[0].memref.buffer, ta_params[0].memref.size);
        if(!tmp){
            TEE_Free(ta_params[0].memref.buffer);
            return TEE_ERROR_OUT_OF_MEMORY;
        }else ta_params[0].memref.buffer = tmp;
    }

    res = TEE_OpenTASession(&ta_uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &sess, &eo);
    if(res)
        return res;
    res = TEE_InvokeTACommand(sess,
                              TEE_TIMEOUT_INFINITE,
                              params[1].value.a,
                              pt, ta_params,
                              &eo);
    TEE_CloseTASession(sess);

    if(res)
        return res;

    res = encrypt_payload(s_ke,
                          ta_params[0].memref.buffer, ta_params[0].memref.size,
                          params[2].memref.buffer, &params[2].memref.size);

    TEE_Free(ta_params[0].memref.buffer);
    return res;
}


TEE_Result TA_CreateEntryPoint(void){
    return TEE_SUCCESS;
}


void TA_DestroyEntryPoint(void){

}


/*
 * Requests the attestation of a buffer of data
 */
static TEE_Result attest(TEE_Param params[]){
    TEE_Result res;
    TEE_TASessionHandle sess;
    TEE_UUID au = ATTEST_PTA_UUID;
    uint32_t eo, pt;

    res = TEE_OpenTASession(&au, TEE_TIMEOUT_INFINITE, 0, NULL, &sess, &eo);
    if(res)
        return res;

    pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                         TEE_PARAM_TYPE_MEMREF_OUTPUT,
                         TEE_PARAM_TYPE_NONE,
                         TEE_PARAM_TYPE_NONE);

    res = TEE_InvokeTACommand(sess,
                              TEE_TIMEOUT_INFINITE,
                              ATTEST_PTA_CMD_SIGN,
                              pt, params,
                              &eo);

    TEE_CloseTASession(sess);
    return res;
}

/*
 * Generates the DH parameters and returns the public part
 * Executed once at startup
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param params[4], void **s_id_ptr){
    TEE_Result res = TEE_SUCCESS;
    struct ke_session *sess;
    mbedtls_ecdh_context *dh_ctx;
    size_t olen = 0;
    uint32_t e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,                       // DH parameters
                                    TEE_PARAM_TYPE_MEMREF_OUTPUT,                       // Attestation signature
                                    TEE_PARAM_TYPE_MEMREF_OUTPUT | TEE_PARAM_TYPE_NONE, // Device certificate (optional)
                                    TEE_PARAM_TYPE_NONE);

    if(pt != e_pt)
        return TEE_ERROR_BAD_PARAMETERS;

    dh_ctx = TEE_Malloc(sizeof(mbedtls_ecdh_context), TEE_MALLOC_FILL_ZERO);
    if(!dh_ctx){
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    mbedtls_ecdh_init(dh_ctx);
    if(mbedtls_ecdh_setup(dh_ctx, MBEDTLS_ECP_DP_SECP256R1)){
        res = TEE_ERROR_SECURITY;
        goto free_ecdh;
    }

    res = mbedtls_ecdh_make_params(dh_ctx, &olen,
                                   params[0].memref.buffer, params[0].memref.size,
                                   f_rng, NULL);
    if(res){
        res = TEE_ERROR_SECURITY;
        goto free_ecdh;
    }

    params[0].memref.size = olen;

    res = attest(params);
    if(res){
        res = TEE_ERROR_SECURITY;
        goto free_ecdh;
    }

    // Check if Caller/Client expects device certificate
    if(TEE_PARAM_TYPE_GET(pt, 2) == TEE_PARAM_TYPE_MEMREF_OUTPUT){
        pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                             TEE_PARAM_TYPE_NONE,
                             TEE_PARAM_TYPE_NONE,
                             TEE_PARAM_TYPE_NONE);

        res = get_device_cert(NULL, pt, &params[2]);
        if(res){
            res = TEE_ERROR_SECURITY;
            goto free_ecdh;
        }
    }

    sess = TEE_Malloc(sizeof(struct ke_session), TEE_MALLOC_FILL_ZERO);
    if(!sess){
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto free_ecdh;
    }

    sess->dh_ctx = dh_ctx;
    *s_id_ptr = sess;

    return TEE_SUCCESS;

free_ecdh:
    mbedtls_ecdh_free(dh_ctx);
    TEE_Free(dh_ctx);
out:
    return res;
}


void TA_CloseSessionEntryPoint(void *s_ptr){
    TEE_Free(s_ptr);
}


TEE_Result TA_InvokeCommandEntryPoint(void *s_ptr, uint32_t cmd_id, uint32_t pt, 
                                      TEE_Param params[TEE_NUM_PARAMS]){
    switch(cmd_id){
    case TA_KE_INIT:
        return init_ke(s_ptr, pt, params);
    case TA_KE_GET_DC:
        return get_device_cert(s_ptr, pt, params);
    case TA_KE_INSTALL_TA:
        return install_ta(s_ptr, pt, params);
    case TA_KE_CMD_TA:
        return cmd_ta(s_ptr, pt, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
