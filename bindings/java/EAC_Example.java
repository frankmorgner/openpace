import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

public class EAC_Example {
	static {
		System.loadLibrary("jeac");
	}

    public static void main(String argv[]) {
        final byte[] EF_CARDACCESS = new BigInteger("318182300D060804007F00070202020201023012060A04007F000702020302020201020201413012060A04007F0007020204020202010202010D301C060904007F000702020302300C060704007F0007010202010D020141302B060804007F0007020206161F655041202D2042447220476D6248202D20546573746B617274652076322E3004491715411928800A01B421FA07000000000000000000000000000000000000201010291010", 16).toByteArray();
        final String pin = "123456";
        byte[] PIN = null;
        try {
            PIN = pin.getBytes("ISO-8859-1");
        } catch (UnsupportedEncodingException ex) {
        }

        eac.EAC_init();

        SWIGTYPE_p_PACE_SEC secret = eac.PACE_SEC_new(PIN, s_type.PACE_PIN);

        SWIGTYPE_p_BUF_MEM buf = eac.get_buf(EF_CARDACCESS);
        eac.hexdump("EF.CardAccess", buf);

        //System.out.println("Secret:");
        //System.out.println(eac.PACE_SEC_print_private(secret, 4));

        SWIGTYPE_p_EAC_CTX picc_ctx = eac.EAC_CTX_new();
        SWIGTYPE_p_EAC_CTX pcd_ctx = eac.EAC_CTX_new();
        eac.EAC_CTX_init_ef_cardaccess(EF_CARDACCESS, pcd_ctx);
        eac.EAC_CTX_init_ef_cardaccess(EF_CARDACCESS, picc_ctx);

        System.out.println("PACE step 1");
        SWIGTYPE_p_BUF_MEM enc_nonce = eac.PACE_STEP1_enc_nonce(picc_ctx, secret);

        System.out.println("PACE step 2");
        eac.PACE_STEP2_dec_nonce(pcd_ctx, secret, enc_nonce);

        System.out.println("PACE step 3A");
        SWIGTYPE_p_BUF_MEM pcd_mapping_data = eac.PACE_STEP3A_generate_mapping_data(pcd_ctx);
        SWIGTYPE_p_BUF_MEM picc_mapping_data = eac.PACE_STEP3A_generate_mapping_data(picc_ctx);

        eac.PACE_STEP3A_map_generator(pcd_ctx, picc_mapping_data);
        eac.PACE_STEP3A_map_generator(picc_ctx, pcd_mapping_data);

        System.out.println("PACE step 3B");
        SWIGTYPE_p_BUF_MEM pcd_ephemeral_pubkey = eac.PACE_STEP3B_generate_ephemeral_key(pcd_ctx);
        SWIGTYPE_p_BUF_MEM picc_ephemeral_pubkey = eac.PACE_STEP3B_generate_ephemeral_key(picc_ctx);

        eac.PACE_STEP3B_compute_shared_secret(pcd_ctx, picc_ephemeral_pubkey);
        eac.PACE_STEP3B_compute_shared_secret(picc_ctx, pcd_ephemeral_pubkey);

        System.out.println("PACE step 3C");
        eac.PACE_STEP3C_derive_keys(pcd_ctx);
        eac.PACE_STEP3C_derive_keys(picc_ctx);

        System.out.println("PACE step 3D");
        SWIGTYPE_p_BUF_MEM pcd_token = eac.PACE_STEP3D_compute_authentication_token(pcd_ctx, picc_ephemeral_pubkey);
        SWIGTYPE_p_BUF_MEM picc_token = eac.PACE_STEP3D_compute_authentication_token(picc_ctx, pcd_ephemeral_pubkey);

        eac.PACE_STEP3D_verify_authentication_token(pcd_ctx, picc_token);
        int r = eac.PACE_STEP3D_verify_authentication_token(picc_ctx, pcd_token);

        //System.out.println("PICC's EAC_CTX:");
        //System.out.println(eac.EAC_CTX_print_private(picc_ctx, 4));
        //System.out.println("PCD's EAC_CTX:");
        //System.out.println(eac.EAC_CTX_print_private(pcd_ctx, 4));

        eac.EAC_CTX_clear_free(pcd_ctx);
        eac.EAC_CTX_clear_free(picc_ctx);
        eac.PACE_SEC_clear_free(secret);

        eac.EAC_cleanup();

        if (r != 1)
            System.out.println("Result was: " + r);
    }
}
