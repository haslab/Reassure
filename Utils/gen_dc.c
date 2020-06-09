// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2020, Miguel Quaresma
#include<stdio.h>
#include<unistd.h>
#include<fcntl.h>
#include<inttypes.h>
#include<string.h>
#include<mbedtls/pk.h>
#include<mbedtls/ecdsa.h>
#include<mbedtls/x509_crt.h>
#include<mbedtls/ctr_drbg.h>
#include<mbedtls/entropy.h>
#include<mbedtls/error.h>
#include<mbedtls/aes.h>

/*
 * Sets up a random number generator
 */
int init_ctrdrbg_ctx(mbedtls_ctr_drbg_context *rng){
    int err_cd = 0;
    mbedtls_entropy_context etp;

    mbedtls_ctr_drbg_init(rng);
    mbedtls_entropy_init(&etp);
    
    err_cd = mbedtls_ctr_drbg_seed(rng, mbedtls_entropy_func, &etp, NULL, 0);

    return err_cd;
}


/*
 * Generates the keypair used in attestation
 */
int gen_pk(mbedtls_pk_context *pk){
    int err_cd = 0;
    mbedtls_ctr_drbg_context rng;
    
    mbedtls_pk_init(pk);
    err_cd = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if(!err_cd){
        err_cd = init_ctrdrbg_ctx(&rng);
        if(!err_cd)
            err_cd = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*pk), mbedtls_ctr_drbg_random, &rng);
    }
    
    return err_cd;
}


int encrypt_key(void *pk, size_t len){
    int err_cd = 0;
    const mbedtls_md_info_t *md_t = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_aes_context enc;
    void *key = calloc(16, sizeof(uint8_t));
    void *tmp = calloc(32, sizeof(uint8_t));
    uint32_t huk_subkey_usage = 0x00005;
    size_t off = 0;

    err_cd = mbedtls_md_hmac(md_t, key, 16, &huk_subkey_usage, sizeof(huk_subkey_usage), tmp);
    if(err_cd)
        goto exit;
    
    mbedtls_aes_init(&enc);
    err_cd = mbedtls_aes_setkey_enc(&enc, tmp, 128);
    if(err_cd)
        goto exit;

    err_cd = mbedtls_aes_crypt_ctr(&enc, len, &off, key, tmp, pk, pk);
    if(err_cd)
        goto exit;
exit:
    free(key);
    free(tmp);
    mbedtls_aes_free(&enc);
    return err_cd;
}


void print_key(mbedtls_mpi *val){
    char str[1024] = {0};
    size_t len;

    if(!mbedtls_mpi_write_string(val, 10, str, 1024 * sizeof(char), &len))
        printf("%s\n", str);
}


int write_key(mbedtls_pk_context *pk){
    int err_cd = 0, fd;
    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*pk);
    size_t bytes = mbedtls_mpi_size(&(ec->d));
    void *buf = calloc(bytes+1, sizeof(uint8_t));
    const char key_dump_txt[] = "ak.txt";
    const char key_dump_enc[] = "ak.enc";

    print_key(&(ec->d));
    print_key(&(ec->Q.X));
    print_key(&(ec->Q.Y));

    err_cd = mbedtls_mpi_write_binary(&(ec->d), buf, bytes);
    if(err_cd)
        goto exit;

    fd = open(key_dump_txt, O_CREAT | O_WRONLY, 0644);
    if(fd > 0){
        write(fd, buf, bytes);
        close(fd);
    }

    err_cd = encrypt_key(buf, bytes);
    if(err_cd)
        goto exit;

    fd = open(key_dump_enc, O_CREAT | O_WRONLY, 0644);
    if(fd > 0){
        write(fd, buf, bytes);
        err_cd = mbedtls_mpi_write_binary(&(ec->Q.X), buf, bytes);
        if(err_cd)
            goto exit;
        write(fd, buf, bytes);
        err_cd = mbedtls_mpi_write_binary(&(ec->Q.Y), buf, bytes);
        if(err_cd)
            goto exit;
        write(fd, buf, bytes);
        close(fd);
    }


exit:
    free(buf);
    return err_cd;
}


/*
 * Generates a device certificate
 */
int gen_crt(mbedtls_x509write_cert *dc, mbedtls_pk_context *pk){
    int err_cd = 0, fd;
    const char dc_info[] = "C=PT,O=Haslab,CN=Haslab Device";
    const char not_before[] = "20191231235959";
    const char not_after[] = "20211231235959";
    mbedtls_mpi serial;
    mbedtls_ctr_drbg_context rng;
    char cert_dump_f[] = "DC.der";
    char *cert_der_buf = calloc(1024, sizeof(uint8_t));
    size_t tmp;
    
    mbedtls_x509write_crt_init(dc);

    mbedtls_x509write_crt_set_subject_key(dc, pk);
    mbedtls_x509write_crt_set_issuer_key(dc, pk);

    err_cd = mbedtls_x509write_crt_set_subject_name(dc, dc_info);
    if(err_cd)
        goto exit;
    err_cd = mbedtls_x509write_crt_set_issuer_name(dc, dc_info);
    if(err_cd)
        goto exit;

    mbedtls_x509write_crt_set_version(dc, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(dc, MBEDTLS_MD_SHA256);

    err_cd = init_ctrdrbg_ctx(&rng);
    if(err_cd)
        goto exit;
    
    mbedtls_mpi_init(&serial);
    err_cd = mbedtls_mpi_fill_random(&serial, 8, mbedtls_ctr_drbg_random, &rng);
    if(err_cd)
        goto exit;

    err_cd = mbedtls_x509write_crt_set_serial(dc, &serial);
    if(err_cd)
        goto exit;

    err_cd = mbedtls_x509write_crt_set_validity(dc, not_before, not_after);
    if(err_cd)
        goto exit;

    err_cd = mbedtls_x509write_crt_set_basic_constraints(dc, 1, 0);
    if(err_cd)
        goto exit;
    
    err_cd = mbedtls_x509write_crt_set_subject_key_identifier(dc);
    if(err_cd)
        goto exit;

    err_cd = mbedtls_x509write_crt_set_authority_key_identifier(dc);
    if(err_cd)
        goto exit;

    err_cd = mbedtls_x509write_crt_set_key_usage(dc, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_NON_REPUDIATION);
    if(err_cd)
        goto exit;

    err_cd = mbedtls_x509write_crt_set_ns_cert_type(dc, MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING);
    if(err_cd)
        goto exit;
    
    /* Dump certificate */
    tmp = 1024;
    err_cd = mbedtls_x509write_crt_der(dc, cert_der_buf, tmp, mbedtls_ctr_drbg_random, &rng);
    if(err_cd > 0){
        tmp -= err_cd;
        fd = open(cert_dump_f, O_CREAT | O_WRONLY, 0644);
        if(fd <= 0)
            return -1;

        write(fd, cert_der_buf + tmp, err_cd);
        close(fd);
        err_cd = 0;
    }
    /* Dump private key */
    err_cd = write_key(pk);
    
exit:
    mbedtls_mpi_free(&serial);
    free(cert_der_buf);
    mbedtls_x509write_crt_free(dc);
    mbedtls_pk_free(pk);
    return err_cd;
}


int parse_crt(void){
    int err_cd = 0, fd;
    mbedtls_x509_crt dc;
    const char cert_dump_f[] = "DC.der";
    char *buf = calloc(1024, sizeof(uint8_t));
    size_t tmp = 1024;

    mbedtls_x509_crt_init(&dc);
    fd = open(cert_dump_f, O_RDONLY);
    if(fd > 0){
        tmp = read(fd, buf, tmp);
        close(fd);
        err_cd = mbedtls_x509_crt_parse_der(&dc, buf, tmp);
        if(err_cd)
            goto exit;

        memset(buf, 0, tmp);
        tmp = 1024;
        err_cd = mbedtls_x509_crt_info(buf, tmp, "", &dc);
        if(err_cd > 0){
            fprintf(stderr, "%s\n", buf);
            err_cd = 0;
        }
    }

exit:
    free(buf);
    mbedtls_x509_crt_free(&dc);
    return err_cd;
}


int verify_sig(){
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
        goto exit;

    mbedtls_ecdsa_init(&pk);

    err_cd = mbedtls_ecdsa_from_keypair(&pk, mbedtls_pk_ec(crt.pk));
    if(err_cd)
        goto exit;

    fd = open("CSR.raw", O_RDONLY);
    if(fd < 0)
        goto exit;

    buf_l = read(fd, buf, buf_l);
    close(fd);
    if(buf_l < 0)
        goto exit;

    err_cd = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                        buf+64, buf_l-64,
                        buf+64);
    if(err_cd)
        goto exit;

    fprintf(stderr, "HERE\n");
    err_cd = mbedtls_ecdsa_read_signature(&pk, buf+64, 32, buf, 64);
    if(err_cd)
        goto exit;

    fprintf(stderr, "OK\n");

exit:
    mbedtls_x509_crt_free(&crt);
    return err_cd;
}



int parse_args(int argc, char *argv[]){
    int bm = 0;
    return bm;
}

int main(int argc, char *argv[]){
    int err_cd = 0;
    char *err = calloc(1024, sizeof(uint8_t));
    mbedtls_pk_context pk;
    mbedtls_x509write_cert dc;

    if(argc > 1 && !strcmp(*++argv, "-v"))
        err_cd = verify_sig();
    else{
        err_cd = gen_pk(&pk);

        if(!err_cd)
            err_cd = gen_crt(&dc, &pk);

        err_cd = parse_crt();
    }

    if(err_cd){
        mbedtls_strerror(err_cd, err, 1024);
        fprintf(stderr, "%s\n", err);
    }

    free(err);
    return err_cd;
}
