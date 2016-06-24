/*
 * Copyright (c) 2010-2012 Dominik Oepen
 *
 * This file is part of OpenPACE.
 *
 * OpenPACE is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * OpenPACE is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * OpenPACE.  If not, see <http://www.gnu.org/licenses/>.
 */

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

class PACEEntity {
    protected SWIGTYPE_p_PACE_SEC secret;
    protected SWIGTYPE_p_BUF_MEM encoded_nonce;
    protected SWIGTYPE_p_EAC_CTX eac_context;
    protected SWIGTYPE_p_BUF_MEM ephemeral_key;
    protected SWIGTYPE_p_BUF_MEM opp_pub;

    public PACEEntity(String sec, s_type secret_type, byte[] ef_card_access) throws NullPointerException {
        byte[] byte_sec = null;
        try {
            byte_sec = sec.getBytes("ISO-8859-1");
        } catch (UnsupportedEncodingException ex) {
        }

        this.encoded_nonce = null;

        this.secret = eac.PACE_SEC_new(byte_sec, secret_type);
        if (this.secret == null)
            throw new NullPointerException("Failed to initialize secret");

        this.eac_context = eac.EAC_CTX_new();
        if (this.eac_context == null)
            throw new NullPointerException("Failed to create EAC context");

        if (eac.EAC_CTX_init_ef_cardaccess(ef_card_access, this.eac_context) == 0)
            throw new NullPointerException("Failed to initialize EAC context from EF.CardAccess");

        this.ephemeral_key = null;
    }

    public SWIGTYPE_p_BUF_MEM generate_static_key() {
        SWIGTYPE_p_BUF_MEM static_key;
        static_key = eac.PACE_STEP3A_generate_mapping_data(this.eac_context);
        if (static_key == null)
            throw new NullPointerException("Failed to generate static key");
        return static_key;
    }

    public void map_generator(SWIGTYPE_p_BUF_MEM opp_static_pub) {
        eac.PACE_STEP3A_map_generator(this.eac_context, opp_static_pub);
    }

    public SWIGTYPE_p_BUF_MEM generate_ephemeral_key() {
        this.ephemeral_key = eac.PACE_STEP3B_generate_ephemeral_key(this.eac_context);
        if (this.ephemeral_key == null)
            throw new NullPointerException("Failed to generate ephemeral key");
        return this.ephemeral_key;
    }

    public void compute_shared_secret(SWIGTYPE_p_BUF_MEM opp_pub) {
        this.opp_pub = opp_pub;
        if (eac.PACE_STEP3B_compute_shared_secret(this.eac_context,
                opp_pub) == 0)
            throw new NullPointerException("Failed to compute shared secret");
    }

    public void derive_keys() {
        if (eac.PACE_STEP3C_derive_keys(this.eac_context) == 0)
            throw new NullPointerException("Failed to derive keys");
        if (eac.EAC_CTX_set_encryption_ctx(this.eac_context, eac.EAC_ID_PACE) == 0)
            throw new NullPointerException("Failed to initialize Secure Messaging context");

    }
}

class PICC extends PACEEntity {
    public PICC(String sec, s_type secret_type, byte[] ef_card_access) {
        super(sec, secret_type, ef_card_access);
    }

    public SWIGTYPE_p_BUF_MEM generate_nonce() throws NullPointerException {

        this.encoded_nonce = eac.PACE_STEP1_enc_nonce(this.eac_context, this.secret);
        if (this.encoded_nonce == null)
            throw new NullPointerException("Failed to generate nonce");
        return this.encoded_nonce;
    }

    public int verify_authentication_token(SWIGTYPE_p_BUF_MEM token) {
        int ret;
        ret = eac.PACE_STEP3D_verify_authentication_token(this.eac_context, token);
        if (eac.EAC_CTX_set_encryption_ctx(this.eac_context, eac.EAC_ID_PACE) == 0)
            throw new NullPointerException("Failed to initialize Secure Messaging context");
        return ret;
    }

    public SWIGTYPE_p_BUF_MEM get_id() throws NullPointerException {
        SWIGTYPE_p_BUF_MEM ret;
        ret = eac.EAC_Comp(this.eac_context, eac.EAC_ID_PACE, this.ephemeral_key);
        if (ret == null)
            throw new NullPointerException("Failed to get ID_PICC");
        return ret;
    }
}

class PCD extends PACEEntity {
    public PCD(String sec, s_type secret_type, byte[] ef_card_access) {
        super(sec, secret_type, ef_card_access);
    }

    public void decode_nonce(SWIGTYPE_p_BUF_MEM enc_nonce) {
        this.encoded_nonce = enc_nonce;
        eac.PACE_STEP2_dec_nonce(this.eac_context, this.secret, this.encoded_nonce);
    }

    public SWIGTYPE_p_BUF_MEM compute_authentication_token() {
        SWIGTYPE_p_BUF_MEM ret;
        ret = eac.PACE_STEP3D_compute_authentication_token(this.eac_context, this.opp_pub);
        return ret;
    }
}

public class JPace {
	static {
		System.loadLibrary("jeac");
	}

	public static void main(String argv[]) {
    	SWIGTYPE_p_BUF_MEM tmp_buf, picc_static_pub, pcd_static_pub;
    	SWIGTYPE_p_BUF_MEM picc_eph_pub, pcd_eph_pub, token, id_picc;
        int result;
        final String ef_card_access_str = "318182300D060804007F00070202020201023012060A04007F000702020302020201020201413012060A04007F0007020204020202010202010D301C060904007F000702020302300C060704007F0007010202010D020141302B060804007F0007020206161F655041202D2042447220476D6248202D20546573746B617274652076322E3004491715411928800A01B421FA07000000000000000000000000000000000000201010291010";
        final byte[] ef_card_access = new BigInteger(ef_card_access_str, 16).toByteArray();

        System.out.println("Loaded pace library");

        PICC picc = new PICC("123456", s_type.PACE_PIN, ef_card_access);
        PCD pcd = new PCD("123456", s_type.PACE_PIN, ef_card_access);
        if ((picc == null) || (pcd == null))
            throw new NullPointerException("Could not initialize context");

        tmp_buf = picc.generate_nonce();

        pcd.decode_nonce(tmp_buf);
        picc_static_pub = picc.generate_static_key();
        pcd_static_pub = pcd.generate_static_key();

        if ((picc_static_pub == null) || (pcd_static_pub == null))
            throw new NullPointerException("Could not generate public keys");

        picc.map_generator(pcd_static_pub);
        pcd.map_generator(picc_static_pub);
        picc_eph_pub = picc.generate_ephemeral_key();
        pcd_eph_pub = pcd.generate_ephemeral_key();
        picc.compute_shared_secret(pcd_eph_pub);
        pcd.compute_shared_secret(picc_eph_pub);
        picc.derive_keys();
        pcd.derive_keys();

        token = pcd.compute_authentication_token();
        if (token == null)
            throw new NullPointerException("PCD failed to generate authentication token");
        result = picc.verify_authentication_token(token);

        id_picc = picc.get_id();
        System.out.println("Result was: " + result);
	}
}
