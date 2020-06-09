#include<inttypes.h>
#include<tee_internal_api.h>
#include<tee_internal_api_extensions.h>
#include<string.h>
#include<ping_pong_ta.h>

static TEE_Result ping_pong(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS]){
    uint32_t e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE);

    if(e_pt != pt)
        return TEE_ERROR_BAD_PARAMETERS;

    memset(params[0].memref.buffer, 0, params[0].memref.size);

    memcpy(params[0].memref.buffer, "pong", 4);
    params[0].memref.size = 5;

    return TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void){
    return TEE_SUCCESS;
}


void TA_DestroyEntryPoint(void){

}


TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused pt, TEE_Param __unused params[4], void __unused **s_id_ptr){
    return TEE_SUCCESS;
}


void TA_CloseSessionEntryPoint(void *s_ptr){
    TEE_Free(s_ptr);
}


TEE_Result TA_InvokeCommandEntryPoint(void __unused *s_ptr, uint32_t cmd_id, uint32_t pt, 
                                      TEE_Param params[TEE_NUM_PARAMS]){
    switch(cmd_id){
        case TA_PP_CMD:
            return ping_pong(pt, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
