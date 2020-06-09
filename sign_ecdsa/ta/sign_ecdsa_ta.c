#include<inttypes.h>
#include<tee_internal_api.h>
#include<sign_ecdsa_ta.h>

struct ecdsa_instance{
    void *key_obj_id;
    uint32_t key_obj_id_size;
};

struct ecdsa_session{
    TEE_ObjectHandle key;
};

const int nist_p256 = TEE_ECC_CURVE_NIST_P256;

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
    if(res)
        return res;

    params[2].value.a = (res == TEE_SUCCESS);    

    TEE_FreeOperation(op);
    TEE_Free(sha256_dgst);

    return TEE_SUCCESS;
}


/* 
 * Create ECDSA key-pair for TA instance (one per device)
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
    TEE_InitValueAttribute(attrs, TEE_ATTR_ECC_CURVE, nist_p256, 0);
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

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param param[4], void **s_id_ptr){
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

    TEE_CloseObject(s_p->key);
    TEE_Free(s_ptr);
}


TEE_Result TA_InvokeCommandEntryPoint(void *s_ptr, uint32_t cmd_id, uint32_t pt, TEE_Param params[TEE_NUM_PARAMS]){
    switch(cmd_id){
    case TA_ECDSA_CMD_GET_KEY:
        return get_ecdsa_key(s_ptr, pt, params);
    case TA_ECDSA_CMD_SIGN:
        return sign(s_ptr, pt, params);
    case TA_ECDSA_CMD_VERIFY:
        return verify(s_ptr, pt, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
