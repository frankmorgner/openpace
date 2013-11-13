EF_CARDACCESS = ["318182300D060804007F00070202020201023012060A04007F000702020302020201020201413012060A04007F0007020204020202010202010D301C060904007F000702020302300C060704007F0007010202010D020141302B060804007F0007020206161F655041202D2042447220476D6248202D20546573746B617274652076322E3004491715411928800A01B421FA07000000000000000000000000000000000000201010291010"].pack('H*')
PIN = "123456"

require 'eac'
Eac.EAC_init()

secret = Eac.PACE_SEC_new(PIN, Eac::PACE_PIN)

buf = Eac.get_buf(EF_CARDACCESS)
Eac.hexdump("EF.CardAccess", buf)

puts "Secret:"
puts Eac.PACE_SEC_print_private(secret, 4)

picc_ctx = Eac.EAC_CTX_new()
pcd_ctx = Eac.EAC_CTX_new()
Eac.EAC_CTX_init_ef_cardaccess(EF_CARDACCESS, pcd_ctx)
Eac.EAC_CTX_init_ef_cardaccess(EF_CARDACCESS, picc_ctx)

puts "PACE step 1"
enc_nonce = Eac.PACE_STEP1_enc_nonce(picc_ctx, secret)

puts "PACE step 2"
Eac.PACE_STEP2_dec_nonce(pcd_ctx, secret, enc_nonce)

puts "PACE step 3A"
pcd_mapping_data = Eac.PACE_STEP3A_generate_mapping_data(pcd_ctx)
picc_mapping_data = Eac.PACE_STEP3A_generate_mapping_data(picc_ctx)

Eac.PACE_STEP3A_map_generator(pcd_ctx, picc_mapping_data)
Eac.PACE_STEP3A_map_generator(picc_ctx, pcd_mapping_data)

puts "PACE step 3B"
pcd_ephemeral_pubkey = Eac.PACE_STEP3B_generate_ephemeral_key(pcd_ctx)
picc_ephemeral_pubkey = Eac.PACE_STEP3B_generate_ephemeral_key(picc_ctx)

Eac.PACE_STEP3B_compute_shared_secret(pcd_ctx, picc_ephemeral_pubkey)
Eac.PACE_STEP3B_compute_shared_secret(picc_ctx, pcd_ephemeral_pubkey)

puts "PACE step 3C"
Eac.PACE_STEP3C_derive_keys(pcd_ctx)
Eac.PACE_STEP3C_derive_keys(picc_ctx)

puts "PACE step 3D"
pcd_token = Eac.PACE_STEP3D_compute_authentication_token(pcd_ctx, picc_ephemeral_pubkey)
picc_token = Eac.PACE_STEP3D_compute_authentication_token(picc_ctx, pcd_ephemeral_pubkey)

Eac.PACE_STEP3D_verify_authentication_token(pcd_ctx, picc_token)
r = Eac.PACE_STEP3D_verify_authentication_token(picc_ctx, pcd_token)

puts "PICC's EAC_CTX:"
puts Eac.EAC_CTX_print_private(picc_ctx, 4)
puts "PCD's EAC_CTX:"
puts Eac.EAC_CTX_print_private(pcd_ctx, 4)

Eac.EAC_CTX_clear_free(pcd_ctx)
Eac.EAC_CTX_clear_free(picc_ctx)
Eac.PACE_SEC_clear_free(secret)

Eac.EAC_cleanup()

if r != 1
    exit 1
end
