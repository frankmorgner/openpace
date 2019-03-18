#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

const unsigned char EF_CARDACCESS[] = { 0x31, 0x81, 0x82, 0x30, 0x0D, 0x06, 0x08, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x01, 0x02, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x41, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0D, 0x30, 0x1C, 0x06, 0x09, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x30, 0x0C, 0x06, 0x07, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x01, 0x02, 0x02, 0x01, 0x0D, 0x02, 0x01, 0x41, 0x30, 0x2B, 0x06, 0x08, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x06, 0x16, 0x1F, 0x65, 0x50, 0x41, 0x20, 0x2D, 0x20, 0x42, 0x44, 0x72, 0x20, 0x47, 0x6D, 0x62, 0x48, 0x20, 0x2D, 0x20, 0x54, 0x65, 0x73, 0x74, 0x6B, 0x61, 0x72, 0x74, 0x65, 0x20, 0x76, 0x32, 0x2E, 0x30, 0x04, 0x49, 0x17, 0x15, 0x41, 0x19, 0x28, 0x80, 0x0A, 0x01, 0xB4, 0x21, 0xFA, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x10, 0x10, 0x29, 0x10, 0x10, };
const char PIN[] = "123456";

#include <eac/eac.h>
#include <eac/pace.h>
#include <openssl/bio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int r;
    BIO *bio = NULL;
    PACE_SEC *secret = NULL;
    EAC_CTX *picc_ctx = NULL, *pcd_ctx = NULL;
    BUF_MEM *enc_nonce = NULL, *pcd_mapping_data = NULL,
            *picc_mapping_data = NULL, *pcd_ephemeral_pubkey = NULL,
            *picc_ephemeral_pubkey = NULL, *pcd_token = NULL,
            *picc_token = NULL;

    EAC_init();

    puts("EF.CardAccess:");
    bio = BIO_new_fp(stdout, BIO_NOCLOSE|BIO_FP_TEXT);
    BIO_dump_indent(bio, (char *) EF_CARDACCESS, sizeof EF_CARDACCESS, 4);

    secret = PACE_SEC_new(PIN, strlen(PIN), PACE_PIN);

    puts("Secret:");
    PACE_SEC_print_private(bio, secret, 4);

    picc_ctx = EAC_CTX_new();
    pcd_ctx = EAC_CTX_new();
    EAC_CTX_init_ef_cardaccess(EF_CARDACCESS, sizeof EF_CARDACCESS, pcd_ctx);
    EAC_CTX_init_ef_cardaccess(EF_CARDACCESS, sizeof EF_CARDACCESS, picc_ctx);

    puts("PACE step 1");
    enc_nonce = PACE_STEP1_enc_nonce(picc_ctx, secret);

    puts("PACE step 2");
    PACE_STEP2_dec_nonce(pcd_ctx, secret, enc_nonce);

    puts("PACE step 3A");
    pcd_mapping_data = PACE_STEP3A_generate_mapping_data(pcd_ctx);
    picc_mapping_data = PACE_STEP3A_generate_mapping_data(picc_ctx);

    PACE_STEP3A_map_generator(pcd_ctx, picc_mapping_data);
    PACE_STEP3A_map_generator(picc_ctx, pcd_mapping_data);

    puts("PACE step 3B");
    pcd_ephemeral_pubkey = PACE_STEP3B_generate_ephemeral_key(pcd_ctx);
    picc_ephemeral_pubkey = PACE_STEP3B_generate_ephemeral_key(picc_ctx);

    PACE_STEP3B_compute_shared_secret(pcd_ctx, picc_ephemeral_pubkey);
    PACE_STEP3B_compute_shared_secret(picc_ctx, pcd_ephemeral_pubkey);

    puts("PACE step 3C");
    PACE_STEP3C_derive_keys(pcd_ctx);
    PACE_STEP3C_derive_keys(picc_ctx);

    puts("PACE step 3D");
    pcd_token = PACE_STEP3D_compute_authentication_token(pcd_ctx, picc_ephemeral_pubkey);
    picc_token = PACE_STEP3D_compute_authentication_token(picc_ctx, pcd_ephemeral_pubkey);

    r = PACE_STEP3D_verify_authentication_token(pcd_ctx, picc_token);
    if (r == 1)
        r = PACE_STEP3D_verify_authentication_token(picc_ctx, pcd_token);

    puts("PICC's EAC_CTX:");
    EAC_CTX_print_private(bio, picc_ctx, 4);
    puts("PCD's EAC_CTX:");
    EAC_CTX_print_private(bio, pcd_ctx, 4);

    EAC_CTX_clear_free(pcd_ctx);
    EAC_CTX_clear_free(picc_ctx);
    PACE_SEC_clear_free(secret);

    EAC_cleanup();

    if (bio)
        BIO_free_all(bio);
    if (enc_nonce)
        BUF_MEM_free(enc_nonce);
    if (pcd_mapping_data)
        BUF_MEM_free(pcd_mapping_data);
    if (picc_mapping_data)
        BUF_MEM_free(picc_mapping_data);
    if (pcd_ephemeral_pubkey)
        BUF_MEM_free(pcd_ephemeral_pubkey);
    if (picc_ephemeral_pubkey)
        BUF_MEM_free(picc_ephemeral_pubkey);
    if (pcd_token)
        BUF_MEM_free(pcd_token);
    if (picc_token)
        BUF_MEM_free(picc_token);

    if (r != 1)
        return 1;

    return 0;
}
