#include<inttypes.h>
#include<fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<tee_client_api.h>
#include<mbedtls/ecdh.h>
#include<mbedtls/ecp.h>
#include<mbedtls/ctr_drbg.h>
#include<mbedtls/entropy.h>
#include<mbedtls/error.h>
#include<mbedtls/md.h>
#include<mbedtls/ecdsa.h>
#include<mbedtls/x509_crt.h>
#include<mbedtls/pk.h>
#include<mbedtls/cipher.h>
#include<proxy_ta.h>

int read_file(const char *fname, void **buf, size_t *size){
    int fd, res;
    off_t fsize;

    if((fd = open(fname, O_RDONLY))  > 0){
        if((fsize = lseek(fd, 0, SEEK_END)) > 0){
            *buf = calloc(fsize, 1);
            if(*buf){
                *size = fsize;
                lseek(fd, 0, SEEK_SET);
                res = (read(fd, *buf, fsize) < 0);
                if(res)
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

/*
 * Sign key exchange data for authentication with the Secure World
 */
int sign_data(void *data, size_t data_len, void **sig, size_t *sig_len, mbedtls_ctr_drbg_context *rng){
    int res;
    mbedtls_pk_context pk;
    void *md;
    size_t md_l;

    mbedtls_pk_init(&pk);

    res = mbedtls_pk_parse_keyfile(&pk, "CK.pem", NULL);
    if(res)
        goto error;

    md = calloc(32, sizeof(uint8_t));
    if(!md){
        res = 1;
        goto error;
    }
    md_l = 32;

    res = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                     data, data_len,
                     md);
    if(res)
        goto free_md;

    *sig = calloc(64, sizeof(uint8_t));
    if(!sig)
        goto free_md;
    *sig_len = 64;

    res = mbedtls_pk_sign(&pk,
                          MBEDTLS_MD_SHA256,
                          md, md_l,
                          *sig, sig_len,
                          mbedtls_ctr_drbg_random, rng);

free_md:
    free(md);
error:
    mbedtls_pk_free(&pk);
    return res;
}


/*
 * Verify attested (signed) output using locally stored device certificate
 */
int verify_attested_output(void *sig, size_t sig_len, void *data, size_t data_len){
    const mbedtls_md_info_t *md_inf = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int err_cd = 0, fd;
    mbedtls_x509_crt crt;
    mbedtls_ecdsa_context pk;
    void *buf = calloc(1024, sizeof(uint8_t));
    size_t buf_l = 1024;

    fd = open("DC.der", O_RDONLY);
    if(fd < 0)
        goto exit;

    buf_l = read(fd, buf, buf_l);
    close(fd);
    if(buf_l < 0)
        goto exit;

    mbedtls_x509_crt_init(&crt);
    err_cd = mbedtls_x509_crt_parse_der(&crt, buf, buf_l);
    if(err_cd)
        goto free_crt;

    mbedtls_ecdsa_init(&pk);

    err_cd = mbedtls_ecdsa_from_keypair(&pk, mbedtls_pk_ec(crt.pk));
    if(err_cd)
        goto free_pk;

    err_cd = mbedtls_md(md_inf, data, data_len, buf);
    if(err_cd)
        goto free_pk;

    err_cd = mbedtls_ecdsa_read_signature(&pk, buf, mbedtls_md_get_size(md_inf), sig, sig_len);


free_pk:
    mbedtls_ecdsa_free(&pk);
free_crt:
    mbedtls_x509_crt_free(&crt);
exit:
    free(buf);
    return err_cd;
}


static int init_ctrdrbg_ctx(mbedtls_ctr_drbg_context *rng){
    int err_cd = 0;
    mbedtls_entropy_context etp;

    mbedtls_ctr_drbg_init(rng);
    mbedtls_entropy_init(&etp);
    
    err_cd = mbedtls_ctr_drbg_seed(rng, mbedtls_entropy_func, &etp, NULL, 0);

    return err_cd;
}


/*
 * Loads ECDH parameters and generates private and public key
 */
static int create_dh_key(mbedtls_ecdh_context **dh_ctx,
                         mbedtls_ctr_drbg_context *rng,
                         void *dh_params_p, size_t dh_params_s,
                         void *buf, size_t *len){
    int res;
    const unsigned char *dh_params = dh_params_p;
    const unsigned char *dh_params_end = dh_params + dh_params_s;
    size_t tmp;

    *dh_ctx = calloc(1, sizeof(mbedtls_ecdh_context));
    if(!*dh_ctx)
        goto out;

    mbedtls_ecdh_init(*dh_ctx);
    res = mbedtls_ecdh_read_params(*dh_ctx, &dh_params, dh_params_end);
    if(res)
        goto free_dh_ctx;

    res = mbedtls_ecdh_make_public(*dh_ctx, &tmp,
                                   buf, *len,
                                   mbedtls_ctr_drbg_random, rng);
    if(!res){
        *len = tmp;
        goto out;
    }


free_dh_ctx:
    mbedtls_ecdh_free(*dh_ctx);
    *dh_ctx = NULL;
out:
    return res;
}


/*
 * Computes the shared secret of an ECDH instance and
 * initializes an cipher context with that key
 */
static int compute_shared_key(mbedtls_ecdh_context *dh_ctx,
                              mbedtls_cipher_context_t **enc_ctx,
                              mbedtls_cipher_context_t **dec_ctx,
                              mbedtls_ctr_drbg_context *rng){
    int res = 0;
    const mbedtls_md_info_t *md;
    uint8_t tmp[32], sh_key[32];
    size_t len = 32;

    res = mbedtls_ecdh_calc_secret(dh_ctx, &len,
                                   tmp, len,
                                   mbedtls_ctr_drbg_random, rng);
    if(res)
        goto out;

    md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    res = mbedtls_md(md, tmp, len, sh_key);
    if(res)
        goto out;

    *enc_ctx = calloc(1, sizeof(mbedtls_cipher_context_t));
    if(!*enc_ctx){
        res = -1;
        goto out;
    }

    mbedtls_cipher_init(*enc_ctx);
    res = mbedtls_cipher_setup(*enc_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM));
    if(res)
        goto out;

    res = mbedtls_cipher_setkey(*enc_ctx, sh_key, 256, MBEDTLS_ENCRYPT);
    if(res)
        goto out;

    *dec_ctx = calloc(1, sizeof(mbedtls_cipher_context_t));
    if(!*dec_ctx){
        res = -1;
        goto out;
    }

    mbedtls_cipher_init(*dec_ctx);
    res = mbedtls_cipher_setup(*dec_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM));
    if(res)
        goto out;

    res = mbedtls_cipher_setkey(*dec_ctx, sh_key, 256, MBEDTLS_DECRYPT);
    if(res)
        goto out;

out:
    return res;
}


/*
 * Encrypts buffer using shared key
 * ctxt: tag || iv || encrypted data
 */
static int encrypt_payload(mbedtls_cipher_context_t *enc_ctx, mbedtls_ctr_drbg_context *rng, void **buf, size_t *len){
    int res = 0;
    uint8_t *ctxt = NULL;
    size_t iv_len = mbedtls_cipher_get_iv_size(enc_ctx), ctxt_len;

    ctxt = calloc(*len + 16 + iv_len, 1);
    if(!ctxt)
        goto out;

    res = mbedtls_ctr_drbg_random(rng, ctxt + 16, iv_len);
    if(res)
        goto out;

    res = mbedtls_cipher_auth_encrypt(enc_ctx, ctxt + 16, iv_len, NULL, 0,
                                      *buf, *len,  ctxt + 16 + iv_len, &ctxt_len, ctxt, 16);
    if(res)
        goto out;

    memset(*buf, 0, *len);
    free(*buf);

    *buf = ctxt;
    *len = 16 + iv_len + ctxt_len;

out:
    return res;
}

/*
 * Decrypts buffer using shared key
 * buf: tag || iv || encrypted data
 */
static int decrypt_payload(mbedtls_cipher_context_t *dec_ctx, void **buf, size_t *len){
    int res = 0;
    uint8_t *ptxt = NULL;
    size_t iv_len = mbedtls_cipher_get_iv_size(dec_ctx), ptxt_len;

    ptxt = calloc(*len - 16 - iv_len, 1);
    if(!ptxt)
        goto out;
    
    res = mbedtls_cipher_auth_decrypt(dec_ctx, *buf + 16, iv_len, NULL, 0,
                                      *buf + 16 + iv_len, *len - 16 - iv_len, ptxt, &ptxt_len, *buf, 16);
    memset(*buf, 0, *len);
    free(*buf);

    if(res)
        goto out;
    
    *buf = ptxt;
    *len = ptxt_len;
out:    
    return res;
}

/*
 * Opens a session with the Proxy TA; imports the DH public parameters generates its own
 */
void bootstrap_ecdh(TEEC_Context *ctx, TEEC_Session *sess, TEEC_Operation *op, TEEC_UUID *uuid,
                    mbedtls_ecdh_context **dh_ctx, mbedtls_ctr_drbg_context *rng, void *pub_k, size_t *pub_k_len){
    TEEC_Result res;
    uint32_t eo;
    char error_buf[1024] = {0};

    memset(op, 0, sizeof(*op));
    op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, // Public key
                                      TEEC_MEMREF_TEMP_OUTPUT, // Signature
                                      TEEC_MEMREF_TEMP_OUTPUT, // Device certificate (optional)
                                      TEEC_NONE);

    op->params[0].tmpref.buffer = calloc(512, sizeof(uint8_t));
    op->params[0].tmpref.size = 512;
    op->params[1].tmpref.buffer = calloc(512, sizeof(uint8_t));
    op->params[1].tmpref.size = 512;
    op->params[2].tmpref.buffer = calloc(512, sizeof(uint8_t));
    op->params[2].tmpref.size = 512;
    res = TEEC_OpenSession(ctx, sess, uuid,
                           TEEC_LOGIN_PUBLIC, NULL, op, &eo);
    if(res)
        errx(1, "TEEC_OpenSession: %x (error origin %#" PRIx32")", res, eo);

    res = write_file("DC.der", op->params[2].tmpref.buffer, op->params[2].tmpref.size);
    if(res)
        errx(1, "write_file: %x", res);

    free(op->params[2].tmpref.buffer);

    res = verify_attested_output(op->params[1].tmpref.buffer, op->params[1].tmpref.size,
                                 op->params[0].tmpref.buffer, op->params[0].tmpref.size);
    if(res){
        mbedtls_strerror(res, error_buf, 1024);
        errx(1, "verify_attested_output: %x (error meaning %s)", res, error_buf);
    }

    res = create_dh_key(dh_ctx,
                        rng,
                        op->params[0].tmpref.buffer, op->params[0].tmpref.size,
                        pub_k, pub_k_len);

    free(op->params[0].tmpref.buffer);
    free(op->params[1].tmpref.buffer);

    if(res){
        mbedtls_strerror(res, error_buf, 1024);
        errx(1, "create_dh_key: %x (error meaning %s)", res, error_buf);
    }
}


int main(int argc, char *argv[]){
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_Result res;
    TEEC_UUID uuid = TA_KE_UUID;
    mbedtls_ecdh_context *dh_ctx = NULL;
    mbedtls_cipher_context_t *enc_ctx = NULL, *dec_ctx = NULL;
    mbedtls_ctr_drbg_context rng;
    char ta_uuid[42] = {0}, error_buf[1024] = {0};
    void *buf;
    size_t tmp;
    int cmd = -1;
    uint32_t eo;


    res = TEEC_InitializeContext(NULL, &ctx);
    if(res)
        errx(1, "TEEC_InitializeContext: %#" PRIx32 " (error origin %#" PRIx32")", res, eo);

    res = init_ctrdrbg_ctx(&rng);
    if(res){
        mbedtls_strerror(res, error_buf, 1024);
        errx(1, "init_ctrdrbg_ctx: %x (error meaning %s)", res, error_buf);
    }

    buf = calloc(256, sizeof(uint8_t));
    tmp = 256;
    bootstrap_ecdh(&ctx, &sess, &op, &uuid,
                   &dh_ctx, &rng, buf, &tmp);

    while(cmd){
        printf("1 - Initiate key exchange\n");
        printf("2 - Install TA\n");
        printf("3 - Invoke TA CMD\n");
        printf("0 - Exit\n");
        scanf("%d", &cmd);
        switch(cmd){
        case 1:
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, // Signature
                                             TEEC_MEMREF_TEMP_INPUT, // Public key
                                             TEEC_MEMREF_TEMP_INPUT, // Certificate
                                             TEEC_NONE);

            if(!sign_data(buf, tmp, &op.params[0].tmpref.buffer, &op.params[0].tmpref.size, &rng)){

                op.params[1].tmpref.buffer = calloc(tmp, sizeof(uint8_t));

                if(op.params[1].tmpref.buffer){
                    memcpy(op.params[1].tmpref.buffer, buf, tmp);
                    free(buf);
                    op.params[1].tmpref.size = tmp;

                    if(!read_file("CC.der", &op.params[2].tmpref.buffer, &op.params[2].tmpref.size)){
                        res = TEEC_InvokeCommand(&sess, TA_KE_INIT, &op, &eo);

                        if(res) errx(1, "TEEC_InvokeCommand %#" PRIx32 " (error origin %#" PRIx32 ")", res, eo);
                        else {
                            res = compute_shared_key(dh_ctx, &enc_ctx, &dec_ctx, &rng);
                            if(res) {
                                errx(1, "compute_shared_key %#" PRIx32 " (error msg: %s)", res, error_buf);
                                memset(error_buf, 0, sizeof(error_buf));
                            } else printf("ECDH handshake complete!\n");
                        }
                        free(op.params[2].tmpref.buffer);
                    }
                    free(op.params[1].tmpref.buffer);
                }
                free(op.params[0].tmpref.buffer);
            }
            break;
        case 2: //NOT IMPLEMENTED
            memset(&op, 0, sizeof(op));

            printf("1 - Normal TA\n");
            printf("2 - Third party TA\n");
            scanf("%d", &cmd);

            printf("UUID of TA: ");
            scanf("%s", ta_uuid);
            strncat(ta_uuid, ".ta", 4);

            if(!read_file(ta_uuid, &op.params[0].tmpref.buffer, &op.params[0].tmpref.size)){
                if(!encrypt_payload(enc_ctx, &rng, &op.params[0].tmpref.buffer, &op.params[0].tmpref.size)){
                    if(cmd == 2){
                        ta_uuid[1] = 0;
                        strncat(ta_uuid, ".cert", 6);

                        if(read_file(ta_uuid, &op.params[1].tmpref.buffer, &op.params[1].tmpref.size) ||
                           encrypt_payload(enc_ctx, &rng, &op.params[1].tmpref.buffer, &op.params[1].tmpref.size))
                            break;

                        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, // TA binary
                                                         TEEC_MEMREF_TEMP_INPUT, // TA certificate
                                                         TEEC_NONE,
                                                         TEEC_NONE);
                    } else
                        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, // TA binary
                                                         TEEC_NONE,
                                                         TEEC_NONE,
                                                         TEEC_NONE);

                    res = TEEC_InvokeCommand(&sess, TA_KE_INSTALL_TA, &op, &eo);

                    if(res) errx(1, "TEEC_InvokeCommand %#" PRIx32 " (error origin %#" PRIx32 ")", res, eo);
                    else printf("TA installed!\n");
                }
                free(op.params[0].tmpref.buffer);
            }
            break;
        case 3:
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, //TA UUID
                                             TEEC_VALUE_INPUT,       //Command ID
                                             TEEC_MEMREF_TEMP_INOUT, //Data
                                             TEEC_NONE);
            memset(ta_uuid, 0, sizeof(ta_uuid));
            printf("UUID of TA: ");
            scanf("%s", ta_uuid);

            op.params[0].tmpref.size = sizeof(ta_uuid);
            op.params[0].tmpref.buffer = calloc(sizeof(ta_uuid), 1);
            if(op.params[0].tmpref.buffer){
                memcpy(op.params[0].tmpref.buffer, ta_uuid, op.params[0].tmpref.size);

                printf("CMD ID: ");
                scanf("%d", &op.params[1].value.a);

                op.params[2].tmpref.buffer = calloc(32, 1);
                op.params[2].tmpref.size = 32;

                if(!encrypt_payload(enc_ctx, &rng, &op.params[2].tmpref.buffer, &op.params[2].tmpref.size)){
                    res = TEEC_InvokeCommand(&sess, TA_KE_CMD_TA, &op, &eo);
                    if(res) errx(1, "TEEC_InvokeCommand %#" PRIx32 " (error origin %#" PRIx32 ")", res, eo);
                    else{
                        res = decrypt_payload(dec_ctx, &op.params[2].tmpref.buffer, &op.params[2].tmpref.size);
                        if(res)
                            printf("Command executed successfully\n");
                        else{
                            mbedtls_strerror(res, error_buf, 1024);
                            errx(1, "decrypt_payload %#" PRIx32 " (error msg: %s)", res, error_buf);
                            memset(error_buf, 0, 1024);
                        }
                    }
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
