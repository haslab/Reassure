#include<inttypes.h>
#include<fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<tee_client_api.h>
#include<qds_ta.h>

int read_file(const char *fname, void **buf, size_t *size){
    int fd, res;
    off_t fsize;
    if((fd = open(fname, O_RDONLY)) > 0){
        if((fsize = lseek(fd, 0, SEEK_END))> 0){
            *buf = calloc(fsize, 1);
            if(*buf){
                *size = fsize;
                lseek(fd, 0, SEEK_SET);
                res = (read(fd, *buf, fsize) < 0);
                if(res < 0)
                    free(*buf);
            } else res = -1;
        } else res = 1;
        close(fd);
    } else res = 1;

    return res;
}


int write_file(const char *fname, void *buf, size_t size){
    int fd, res = 0;

    fd = open(fname, O_CREAT | O_WRONLY, 0666);
    if(fd > 0){
        if(write(fd, buf, size) < 0)
            res = -1;

        close(fd);
    } else res = -1;

    return res;
}


int main(int argc, char *argv[]){
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_Result res;
    TEEC_UUID uuid = TA_QDS_UUID;
    uint32_t eo;
    int cmd = -1;

    res = TEEC_InitializeContext(NULL, &ctx);
    if(res)
        errx(1, "TEEC_InitializeContext: %#" PRIx32 " (error origin %#" PRIx32")", res, eo);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &eo);
    if(res)
        errx(1, "TEEC_OpenSession: %x (error origin %#" PRIx32")", res, eo);

    while(cmd){
        printf("1 - Generate CSR\n");
        printf("2 - Sign (data in data.txt)\n");
        printf("3 - Authenticate (data in data.txt; signature in sig.txt)\n");
        printf("4 - Dump device certificate\n");
        printf("0 - Exit\n");
        scanf("%d", &cmd);
        switch(cmd){
        case 1:
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, //CSR
                                             TEEC_MEMREF_TEMP_OUTPUT, //Signature
                                             TEEC_NONE,
                                             TEEC_NONE);

            op.params[0].tmpref.buffer = calloc(512, sizeof(uint8_t));
            if(op.params[0].tmpref.buffer){
                op.params[1].tmpref.buffer = calloc(128, sizeof(uint8_t));

                if(op.params[1].tmpref.buffer){
                    op.params[0].tmpref.size = sizeof(uint8_t) << 9;
                    op.params[1].tmpref.size = sizeof(uint8_t) << 7;

                   res = TEEC_InvokeCommand(&sess, TA_QDS_CMD_GEN_CSR, &op, &eo);

                   if(res)
                       errx(1, "TEEC_InvokeCommand %#" PRIx32 " (error origin %#" PRIx32 ")", res, eo);
                   else if(!write_file("csr.pem", op.params[0].tmpref.buffer, op.params[0].tmpref.size)){
                       printf("CSR dumped in csr.pem\n");

                       if(!write_file("csr.sig", op.params[1].tmpref.buffer, op.params[1].tmpref.size))
                           printf("Signature dumped in csr.sig\n");
                   }

                   free(op.params[1].tmpref.buffer);
                }
                free(op.params[0].tmpref.buffer);
            }
            
            break;
        case 2:
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                             TEEC_MEMREF_TEMP_OUTPUT,
                                             TEEC_NONE,
                                             TEEC_NONE);

            if(!read_file("data.txt", &op.params[0].tmpref.buffer, &op.params[0].tmpref.size)){
                op.params[1].tmpref.buffer = malloc(sizeof(uint8_t)*64);
                op.params[1].tmpref.size = sizeof(uint8_t);

                if(op.params[1].tmpref.buffer){
                    res = TEEC_InvokeCommand(&sess, TA_QDS_CMD_SIGN, &op, &eo);
                    if(res)
                        errx(1, "TEEC_InvokeCommand %#" PRIx32 " (error origin %#" PRIx32 ")", res, eo);
                    else if(!write_file("signature.txt", op.params[1].tmpref.buffer, op.params[1].tmpref.size))
                        printf("Signature saved in signature.txt\n");
                    free(op.params[1].tmpref.buffer);
                }
 
                free(op.params[0].tmpref.buffer);
            }else printf("Error reading file: data.txt\n");
            
            break;
        case 3:
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, //data
                                             TEEC_MEMREF_TEMP_INPUT, //signature
                                             TEEC_VALUE_OUTPUT,
                                             TEEC_NONE);
            if(!read_file("data.txt", &op.params[0].tmpref.buffer, &op.params[0].tmpref.size)){

                if(!read_file("signature.txt", &op.params[1].tmpref.buffer, &op.params[1].tmpref.size)){
                    res = TEEC_InvokeCommand(&sess, TA_QDS_CMD_VERIFY, &op, &eo);

                    if(res)
                        errx(1, "TEEC_InvokeCommand %#" PRIx32 " (error origin %#" PRIx32 ")", res, eo);
                    else
                        printf("Authentication %s",  op.params[2].value.a ? "successful\n" : "failed\n");

                    free(op.params[1].tmpref.buffer);                    
                } else printf("An error ocurred while reading signature.txt\n");
                
                free(op.params[0].tmpref.buffer);
            } else printf("An error ocurred while reading data.txt\n");
            
            break;
        case 4:
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                             TEEC_NONE,
                                             TEEC_NONE,
                                             TEEC_NONE);
            op.params[0].tmpref.buffer = calloc(512, sizeof(uint8_t));

            if(op.params[0].tmpref.buffer){
                op.params[0].tmpref.size = sizeof(uint8_t) << 9;

                res = TEEC_InvokeCommand(&sess, TA_QDS_GET_DC, &op, &eo);
                if(res)
                    errx(1, "TEEC_InvokeTA_Command %#" PRIx32 "(error origin %#" PRIx32 ")", res, eo); 
                else{
                    if(!write_file("DC.der", op.params[0].tmpref.buffer, op.params[0].tmpref.size))
                        printf("Saved device certificate in DC.der\n");
                    else
                        fprintf(stderr, "Error opening certificate dump file");
                }
                free(op.params[0].tmpref.buffer);
            }
            break;
        default:
            break;
        }
    }

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    
    return 0;
}
