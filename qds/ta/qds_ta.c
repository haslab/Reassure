#include<inttypes.h>
#include<tee_internal_api.h>
#include<string.h>
#include<qds_ta.h>
#include<mbedtls/x509_csr.h>

struct ecdsa_instance{
    void *key_obj_id;
    uint32_t key_obj_id_size;
};

struct ecdsa_session{
    TEE_ObjectHandle key;
};


/*
 * Returns the public part of the signing key
 */
static TEE_Result get_ecdsa_key(void *s_ptr, uint32_t pt, TEE_Param params[4]){
    TEE_Result res;
    struct ecdsa_session *sp = s_ptr;
    uint32_t e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, //X
                                    TEE_PARAM_TYPE_MEMREF_OUTPUT, //Y
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE);
    
    if(e_pt != pt)
        return TEE_ERROR_BAD_PARAMETERS;

    if(sp->key == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_GetObjectBufferAttribute(sp->key,
                                       TEE_ATTR_ECC_PUBLIC_VALUE_X,
                                       params[0].memref.buffer, &(params[0].memref.size));
    if(res)
        return res;

    res = TEE_GetObjectBufferAttribute(sp->key,
                                       TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                                       params[1].memref.buffer, &(params[1].memref.size));
    if(res)
        return res;

    return TEE_SUCCESS;
}


static int f_rng(void *rng __unused, unsigned char *buf, size_t buf_s){
    TEE_GenerateRandom(buf, buf_s);

    return 0;
}


/* 
 * Converts OPTEE internal representation of ECC keys to MBEDTLS's format
 */
static TEE_Result tee_to_mbedtls_keypair(struct ecdsa_session *sp, mbedtls_pk_context *pk){
    TEE_Result res;
    mbedtls_ecp_keypair *ec = TEE_Malloc(sizeof(mbedtls_ecp_keypair), TEE_MALLOC_FILL_ZERO);
    mbedtls_ecdsa_context *ecdsa_ctx = TEE_Malloc(sizeof(mbedtls_ecdsa_context), TEE_MALLOC_FILL_ZERO);
    void *buf;
    uint32_t bufs;

    mbedtls_ecp_keypair_init(ec);
    mbedtls_ecp_group_load(&ec->grp, MBEDTLS_ECP_DP_SECP256R1);

    // private key/value
    res = TEE_GetObjectBufferAttribute(sp->key,
                                       TEE_ATTR_ECC_PRIVATE_VALUE,
                                       NULL, //gets the amount of space required in bufs
                                       &bufs);
    buf = TEE_Malloc(sizeof(uint8_t)*bufs, TEE_MALLOC_FILL_ZERO);
    res = TEE_GetObjectBufferAttribute(sp->key,
                                       TEE_ATTR_ECC_PRIVATE_VALUE,
                                       buf,
                                       &bufs);
    if(res)
        return res;
    mbedtls_mpi_read_binary(&ec->d, buf, bufs);
    TEE_Free(buf);

    mbedtls_ecp_point_init(&ec->Q);
    mbedtls_mpi_set_bit(&((ec->Q).Z), 0, 1);

    // X coordinate of public key/value
    res = TEE_GetObjectBufferAttribute(sp->key,
                                       TEE_ATTR_ECC_PUBLIC_VALUE_X,
                                       NULL,
                                       &bufs);
    buf = TEE_Malloc(sizeof(uint8_t)*bufs, TEE_MALLOC_FILL_ZERO);
    res = TEE_GetObjectBufferAttribute(sp->key,
                                       TEE_ATTR_ECC_PUBLIC_VALUE_X,
                                       buf,
                                       &bufs);
    if(res)
        return res;
    mbedtls_mpi_read_binary(&((ec->Q).X), buf, bufs);
    TEE_Free(buf);

    // Y coordinate of public key/value
    res = TEE_GetObjectBufferAttribute(sp->key,
                                       TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                                       NULL,
                                       &bufs);
    buf = TEE_Malloc(sizeof(uint8_t)*bufs, TEE_MALLOC_FILL_ZERO);
    res = TEE_GetObjectBufferAttribute(sp->key,
                                       TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                                       buf,
                                       &bufs);
    if(res)
        return res;
    mbedtls_mpi_read_binary(&((ec->Q).Y), buf, bufs);
    TEE_Free(buf);
    
    mbedtls_pk_init(pk);
    if(mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)))
        return TEE_ERROR_GENERIC;

    mbedtls_ecdsa_init(ecdsa_ctx);
    if(mbedtls_ecdsa_from_keypair(ecdsa_ctx, ec))
        return TEE_ERROR_GENERIC;
    
    pk->pk_ctx = ecdsa_ctx;
   
    mbedtls_ecp_keypair_free(ec);
    TEE_Free(ec);

    return TEE_SUCCESS;
}


/* 
 * Requests the attestation of the CSR
 */
static TEE_Result attest_csr(TEE_Param params[]){
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
 * Creates a CSR for the key generated at startup
 */
static TEE_Result gen_csr(void *s_ptr, uint32_t pt, TEE_Param params[4]){
    TEE_Result res;
    struct ecdsa_session *sp = s_ptr;
    mbedtls_x509write_csr *csr_ctx;
    mbedtls_pk_context key_ctx;
    uint32_t e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, // CSR
                                    TEE_PARAM_TYPE_MEMREF_OUTPUT, // Signature
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE);
    
    if(e_pt != pt)
        return TEE_ERROR_BAD_PARAMETERS;

    res = tee_to_mbedtls_keypair(sp, &key_ctx);
    if(res)
        return res;
    
    csr_ctx = TEE_Malloc(sizeof(mbedtls_x509write_csr), TEE_MALLOC_FILL_ZERO);
    mbedtls_x509write_csr_init(csr_ctx);

    mbedtls_x509write_csr_set_key(csr_ctx, &key_ctx);
    if(mbedtls_x509write_csr_set_key_usage(csr_ctx, MBEDTLS_X509_KU_DIGITAL_SIGNATURE))
        return TEE_ERROR_GENERIC;
    
    mbedtls_x509write_csr_set_md_alg(csr_ctx, MBEDTLS_MD_SHA256);
    
    if(mbedtls_x509write_csr_set_subject_name(csr_ctx, "C=PT,O=REASSURE,CN=QDS"))
        return TEE_ERROR_GENERIC;
    
    if(mbedtls_x509write_csr_pem(csr_ctx, (uint8_t*)params[0].memref.buffer, params[0].memref.size, f_rng, NULL))
        return 	TEE_ERROR_GENERIC;

    res = attest_csr(params);
    if(res)
        return res;

    mbedtls_ecdsa_free(key_ctx.pk_ctx);
    mbedtls_pk_free(&key_ctx);
    mbedtls_x509write_csr_free(csr_ctx);
    TEE_Free(csr_ctx);

    return TEE_SUCCESS;
}

/* 
 * Signs a buffer using the ECDSA key generated at startup
 */
static TEE_Result sign(void *s_ptr, uint32_t pt, TEE_Param params[4]){
    TEE_Result res;
    TEE_OperationHandle op;
    struct ecdsa_session *sp = s_ptr;
    void *sha256_dgst = TEE_Malloc(sizeof(uint8_t)*32, TEE_MALLOC_FILL_ZERO);
    uint32_t temp = sizeof(uint8_t)*32;
    uint32_t e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                    TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE);

    if(pt != e_pt)
        return TEE_ERROR_BAD_PARAMETERS;

    if(!sp->key){
        DMSG("No ECDSA key found, exiting...\n");
        return TEE_ERROR_GENERIC;
    }
    
    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res)
        return TEE_ERROR_GENERIC;

    res = TEE_DigestDoFinal(op, params[0].memref.buffer, params[0].memref.size, sha256_dgst, &temp);
    
    if(res)
        return TEE_ERROR_GENERIC;
    
    TEE_FreeOperation(op);
    
    res = TEE_AllocateOperation(&op, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, 256);
    if(res)
        return res;
    
    res = TEE_SetOperationKey(op, sp->key);
    if(res)
        return TEE_ERROR_BAD_STATE;

    res = TEE_AsymmetricSignDigest(op, NULL, 0, sha256_dgst, temp, params[1].memref.buffer, &(params[1].memref.size));

    if(res)
        return res;

    TEE_FreeOperation(op);
    TEE_Free(sha256_dgst);
    
    return TEE_SUCCESS;
}

/* 
 * Verifies the authenticity of a message given its signature
 */
static TEE_Result verify(void *s_ptr, uint32_t pt, TEE_Param params[4]){
    TEE_Result res;
    TEE_OperationHandle op;
    struct ecdsa_session *sp = s_ptr;
    void *sha256_dgst = TEE_Malloc(sizeof(uint8_t)*32, TEE_MALLOC_FILL_ZERO);
    uint32_t temp = sizeof(uint8_t)*32;
    uint32_t e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, //message
                                    TEE_PARAM_TYPE_MEMREF_INPUT, //signature
                                    TEE_PARAM_TYPE_VALUE_OUTPUT, //result
                                    TEE_PARAM_TYPE_NONE);

    if(pt != e_pt)
        return TEE_ERROR_BAD_PARAMETERS;
    
    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if(res)
        return TEE_ERROR_GENERIC;

    res = TEE_DigestDoFinal(op, params[0].memref.buffer, params[0].memref.size, sha256_dgst, &temp);
    if(res)
        return TEE_ERROR_GENERIC;

    TEE_FreeOperation(op);

    res = TEE_AllocateOperation(&op, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY, 256);
    if(res)
        return TEE_ERROR_GENERIC;

    res = TEE_SetOperationKey(op, sp->key);
    if(res)
        return TEE_ERROR_GENERIC;

    res = TEE_AsymmetricVerifyDigest(op, NULL, 0, sha256_dgst, temp, params[1].memref.buffer, params[1].memref.size);
    params[2].value.a = !(res == TEE_ERROR_SIGNATURE_INVALID);

    TEE_FreeOperation(op);
    TEE_Free(sha256_dgst);

    return TEE_SUCCESS;
}


/*
 * Requests the device certificate corresponding to the key used in attestation
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
 * Create ECDSA keypair for TA instance (one per device)
 * Executed the first invocation
 */ 
TEE_Result TA_CreateEntryPoint(void){
    TEE_ObjectHandle t_key, p_key;
    TEE_Result res;
    struct ecdsa_instance *inst = TEE_Malloc(sizeof(struct ecdsa_instance), TEE_MALLOC_FILL_ZERO);

    if(!inst)
        return TEE_ERROR_OUT_OF_MEMORY;

    res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 521, &t_key);
    if(res)
        return res;    
        
    TEE_Attribute attrs[1];
    TEE_InitValueAttribute(attrs, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);
    res = TEE_GenerateKey(t_key, 256, attrs, sizeof(attrs)/sizeof(TEE_Attribute));
    if(res)
        return res;

    inst->key_obj_id = TEE_Malloc(sizeof(uint8_t)*32, TEE_MALLOC_FILL_ZERO);
    inst->key_obj_id_size = 32;
    
    res = TEE_GetObjectBufferAttribute(t_key, TEE_ATTR_ECC_PUBLIC_VALUE_X, inst->key_obj_id, &(inst->key_obj_id_size));
    if(res)
        return res;
    
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     inst->key_obj_id, inst->key_obj_id_size,
                                     TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
                                     t_key,
                                     NULL, 0,
                                     &p_key);
    if(res)
        return res;
    
    TEE_CloseObject(t_key);
    TEE_CloseObject(p_key);
    TEE_SetInstanceData(inst);
    
    return TEE_SUCCESS;
}


void TA_DestroyEntryPoint(void){

}

/*
 * Loads the signing key from Trusted Storage
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param param[4] __unused, void **s_id_ptr){
    TEE_Result res;
    struct ecdsa_instance *inst;
    uint32_t e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE);

    if(pt != e_pt)
        return TEE_ERROR_BAD_PARAMETERS;

    struct ecdsa_session *sess = TEE_Malloc(sizeof(struct ecdsa_session), TEE_MALLOC_FILL_ZERO);

    if(!sess)
        return TEE_ERROR_OUT_OF_MEMORY;

    inst = TEE_GetInstanceData();
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                   inst->key_obj_id, inst->key_obj_id_size,
                                   TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
                                   &sess->key);
    if(res)
        return res;
    *s_id_ptr = sess;
    
    return TEE_SUCCESS;
}


void TA_CloseSessionEntryPoint(void *s_ptr){
    struct ecdsa_session *s_p = s_ptr;

    TEE_Free(s_p);
}


TEE_Result TA_InvokeCommandEntryPoint(void *s_ptr, uint32_t cmd_id, uint32_t pt, TEE_Param params[TEE_NUM_PARAMS]){
    switch(cmd_id){
    case TA_QDS_CMD_GEN_CSR:
        return gen_csr(s_ptr, pt, params);
    case TA_QDS_CMD_GET_KEY:
        return get_ecdsa_key(s_ptr, pt, params);
    case TA_QDS_CMD_SIGN:
        return sign(s_ptr, pt, params);
    case TA_QDS_CMD_VERIFY:
        return verify(s_ptr, pt, params);
    case TA_QDS_GET_DC:
        return get_device_cert(s_ptr, pt, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
