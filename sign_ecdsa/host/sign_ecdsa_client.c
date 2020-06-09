#include<err.h>
#include<errno.h>
#include<fcntl.h>
#include<inttypes.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
 
#include<tee_client_api.h>
#include<sign_ecdsa_ta.h>

void print_buffer(void *buf, size_t len){
    uint8_t *pbyte = buf;
    
    for(int i = 0; i < len; i ++)
        printf("%"PRIx8" ", pbyte[i]);
    printf("\n");

}

int main(int argc, char *argv[]){
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_SIGN_ECDSA_UUID;
    int cmd = -1, fd;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    if(res)
        errx(1, "TEEC_InitializeContext(NULL, x): %#" PRIx32, res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

    if(res)
        errx(1, "TEEC_OpenSession(TEEC_LOGIN_PUBLIC): %#" PRIx32 " (error origin %#" PRIx32 ")", res, err_origin);

    while(cmd){
        printf("1 - Get ECDSA key\n");
        printf("2 - Sign\n");
        printf("3 - Verify\n");
        printf("0 - Exit\n");
        scanf("%d", &cmd);
        switch(cmd){
        case 1:            
            //Save public key
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, //X
                                             TEEC_MEMREF_TEMP_OUTPUT, //Y
                                             TEEC_NONE,
                                             TEEC_NONE);
            op.params[0].tmpref.buffer = malloc(sizeof(uint8_t)*32);
            op.params[0].tmpref.size = sizeof(uint8_t)*32;
            op.params[1].tmpref.buffer = malloc(sizeof(uint8_t)*32);
            op.params[1].tmpref.size = sizeof(uint8_t)*32;
            
            res = TEEC_InvokeCommand(&sess, TA_ECDSA_CMD_GET_KEY, &op, &err_origin);

            if((fd = open("pub.txt", O_CREAT | O_WRONLY, 0644)) > 0){
                if(write(fd, op.params[0].tmpref.buffer, op.params[0].memref.size) > 0)
                    if(write(fd, op.params[1].tmpref.buffer, op.params[1].memref.size) > 0)
                        printf("ECDSA public key saved in pub.txt\n");
                close(fd);
            }
            else
                fprintf(stderr, "%s while opening pub.txt\n", strerror(errno));
            break;
        case 2:
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                             TEEC_MEMREF_TEMP_OUTPUT,
                                             TEEC_NONE,
                                             TEEC_NONE);

            op.params[0].tmpref.buffer = strndup("sadsadas", 8);
            op.params[0].tmpref.size = sizeof(char)*8;
            op.params[1].tmpref.buffer = malloc(sizeof(uint8_t)*64);
            op.params[1].tmpref.size = sizeof(uint8_t)*64;

            res = TEEC_InvokeCommand(&sess, TA_ECDSA_CMD_SIGN, &op, &err_origin);
            if(res)
                fprintf(stderr, "Signing failed\n");

            if((fd = open("signature.txt", O_CREAT | O_RDWR, 0644)) > 0)
                if(write(fd, op.params[1].tmpref.buffer, op.params[1].tmpref.size) != -1)
                    printf("Signature written in signature.txt\n");

            break;
        case 3:
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                             TEEC_MEMREF_TEMP_INPUT,
                                             TEEC_VALUE_OUTPUT,
                                             TEEC_NONE);

            op.params[0].tmpref.buffer = strndup("sadsadas", 8);
            op.params[0].tmpref.size = sizeof(char)*8;
            op.params[1].tmpref.buffer = malloc(sizeof(uint8_t)*64);
            op.params[1].tmpref.size = sizeof(uint8_t)*64;
            
            if(pread(fd, op.params[1].tmpref.buffer, op.params[1].tmpref.size, 0)>0){
                op.params[2].value.a = 0;
            
                res = TEEC_InvokeCommand(&sess, TA_ECDSA_CMD_VERIFY, &op, &err_origin);
                if(res);

                if(op.params[2].value.a) printf("Signature verification succeded!\n");
                else printf("Signature verification failed!\n");
            }
            close(fd);
           
            break;
        default:
            break;
        }
    }

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return 0;
}
