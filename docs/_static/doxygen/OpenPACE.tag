<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<tagfile>
  <compound kind="file">
    <name>ca.h</name>
    <path>/home/fm/Dokumente/openpace/src/eac/</path>
    <filename>ca_8h</filename>
    <includes id="eac_8h" name="eac.h" local="yes" imported="no">eac.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>CA_FLAG_DISABLE_PASSIVE_AUTH</name>
      <anchorfile>ca_8h.html</anchorfile>
      <anchor>a5766da26877961a967490cb6de6901bb</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>CA_disable_passive_authentication</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga28c1d11845924a1cd08461c6a1a765cc</anchor>
      <arglist>(EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>CA_get_pubkey</name>
      <anchorfile>ca_8h.html</anchorfile>
      <anchor>a5819e0a4b3b321e69ebd21661ee84134</anchor>
      <arglist>(const EAC_CTX *ctx, const unsigned char *ef_cardsecurity, size_t ef_cardsecurity_len)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CA_set_key</name>
      <anchorfile>ca_8h.html</anchorfile>
      <anchor>ac91aa5d0a95c6c52ffe98192e63614e9</anchor>
      <arglist>(const EAC_CTX *ctx, const unsigned char *priv, size_t priv_len, const unsigned char *pub, size_t pub_len)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>CA_STEP1_get_pubkey</name>
      <anchorfile>group__caproto.html</anchorfile>
      <anchor>gafdf162f33faea84cb7ff359bb1d5c09d</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>CA_STEP2_get_eph_pubkey</name>
      <anchorfile>group__caproto.html</anchorfile>
      <anchor>gad2aaec726b132e27f50aaa16bfbde574</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CA_STEP3_check_pcd_pubkey</name>
      <anchorfile>group__caproto.html</anchorfile>
      <anchor>ga6f5f7dfc8323a946fec506956018525a</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *comp_pubkey, const BUF_MEM *pubkey)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CA_STEP4_compute_shared_secret</name>
      <anchorfile>group__caproto.html</anchorfile>
      <anchor>ga5ebe4465cab901c4bb94a75c74bf71fa</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *pubkey)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CA_STEP5_derive_keys</name>
      <anchorfile>group__caproto.html</anchorfile>
      <anchor>ga37bfdcc37ae95d411b5919cdd02fa3bf</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *pub, BUF_MEM **nonce, BUF_MEM **token)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CA_STEP6_derive_keys</name>
      <anchorfile>group__caproto.html</anchorfile>
      <anchor>ga34352b58c89ce58c4e3e425bfb20ef45</anchor>
      <arglist>(EAC_CTX *ctx, const BUF_MEM *nonce, const BUF_MEM *token)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>cv_cert.h</name>
    <path>/home/fm/Dokumente/openpace/src/eac/</path>
    <filename>cv__cert_8h</filename>
    <includes id="objects_8h" name="objects.h" local="no" imported="no">eac/objects.h</includes>
    <class kind="struct">cvc_chat_seq_st</class>
    <class kind="struct">cvc_pubkey_st</class>
    <class kind="struct">cvc_discretionary_data_template_seq_st</class>
    <class kind="struct">cvc_cert_body_seq_st</class>
    <class kind="struct">cvc_cert_seq_st</class>
    <class kind="struct">cvc_commcert_seq_st</class>
    <class kind="struct">cvc_certificate_description_st</class>
    <class kind="struct">cvc_cert_request_body_seq_st</class>
    <class kind="struct">cvc_cert_request_seq_st</class>
    <class kind="struct">cvc_cert_authentication_request_seq_st</class>
    <member kind="define">
      <type>#define</type>
      <name>ASN1_APP_IMP</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a94b4346228e7f2dfe7ddef89af1ca4d4</anchor>
      <arglist>(stname, field, type, tag)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ASN1_APP_IMP_OPT</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a98ef9b11d6ecb604ac25fa1287c30993</anchor>
      <arglist>(stname, field, type, tag)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ASN1_APP_EXP_OPT</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a0d89b7dcca78890a2f2fc317bdecbfac</anchor>
      <arglist>(stname, field, type, tag)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>CVC_CERT_dup</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gaf8df0122e9d69243120b62033c4b9474</anchor>
      <arglist>(x)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>CVC_PUBKEY_dup</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga3c3f5a64d45ed99d9c5cfd0a0c61b869</anchor>
      <arglist>(x)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>CVC_CHAT_dup</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gadf010f3a63a21336d1025a3f7814c322</anchor>
      <arglist>(x)</arglist>
    </member>
    <member kind="typedef">
      <type>struct cvc_chat_seq_st</type>
      <name>CVC_CHAT_SEQ</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a67c8d91f1c8ec511b2d549d96f7dd8f0</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>CVC_CHAT_SEQ</type>
      <name>CVC_CHAT</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a397bdd4c39a973f58c75c51c884d2d8a</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct cvc_pubkey_st</type>
      <name>CVC_PUBKEY_BODY</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>ac4a7f8515584948330dda1c4d5707bb1</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct cvc_discretionary_data_template_seq_st</type>
      <name>CVC_DISCRETIONARY_DATA_TEMPLATE_SEQ</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a37165b80c9bdb17cd70ca57f20c35b1c</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>CVC_DISCRETIONARY_DATA_TEMPLATE_SEQ</type>
      <name>CVC_DISCRETIONARY_DATA_TEMPLATE</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a10f55178dfcd3bba9e8ccbafae341f2e</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct cvc_cert_body_seq_st</type>
      <name>CVC_CERT_BODY_SEQ</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a3b75d6bf4d0aac69e05339da1d5ef44c</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>CVC_CERT_BODY_SEQ</type>
      <name>CVC_CERT_BODY</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>aa0d8534105b4b6c804ae40628fca719e</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct cvc_cert_seq_st</type>
      <name>CVC_CERT_SEQ</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>af7131eaf8748a5e5a906ad1dccabcfcf</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>CVC_CERT_SEQ</type>
      <name>CVC_CERT</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>aea535afcbb11c7ac5f77e4edfb825ab4</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct cvc_certificate_description_st</type>
      <name>CVC_CERTIFICATE_DESCRIPTION</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>adf748bf4eb467dbce2b5ea54c3a2062f</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct cvc_cert_request_body_seq_st</type>
      <name>CVC_CERT_REQUEST_BODY_SEQ</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a5fb0fe58283be131b751976c3fd48fcd</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>CVC_CERT_REQUEST_BODY_SEQ</type>
      <name>CVC_CERT_REQUEST_BODY</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>ae24aba1a3035e3c536f785aca5fe5080</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct cvc_cert_request_seq_st</type>
      <name>CVC_CERT_REQUEST_SEQ</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>ab603b01cff646c76e5db0fc5fefcc780</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>CVC_CERT_REQUEST_SEQ</type>
      <name>CVC_CERT_REQUEST</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a3c0041409de1d0ac8fdf5cd8f981b322</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct cvc_cert_authentication_request_seq_st</type>
      <name>CVC_CERT_AUTHENTICATION_REQUEST_SEQ</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a0dd5bef6cecaa4d9a1c4daea9a9a23f6</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>CVC_CERT_AUTHENTICATION_REQUEST_SEQ</type>
      <name>CVC_CERT_AUTHENTICATION_REQUEST</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>ac5ffa8517c061b409d8dd92285b9ce15</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>cvc_terminal_role</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a0203c4d440a0ac1ac0e80963a9c8115a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>CVC_Terminal</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a0203c4d440a0ac1ac0e80963a9c8115aac01726f5220ca8395070e254750af6fd</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>CVC_DV</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a0203c4d440a0ac1ac0e80963a9c8115aae47e5b251c04c991351d4e1f578d44f4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>CVC_DocVer</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a0203c4d440a0ac1ac0e80963a9c8115aae3de1a7addb996e92d516661d2ed5edd</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>CVC_CVCA</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a0203c4d440a0ac1ac0e80963a9c8115aa9cc622972693e5a5fd3010c23003a931</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>CVC_CERT *</type>
      <name>CVC_d2i_CVC_CERT</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga59de291be2953ebf60bce12225fed74f</anchor>
      <arglist>(CVC_CERT **cert, const unsigned char **in, long len)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>i2d_CVC_CERT</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga63dd3f2ebdc39d4a9e0b0af8d12ec655</anchor>
      <arglist>(CVC_CERT *a, unsigned char **out)</arglist>
    </member>
    <member kind="function">
      <type>CVC_CERT *</type>
      <name>CVC_CERT_new</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga90b0e7ddb7b193cbc414f8d88cd9e6cc</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>CVC_CERT_free</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga24e6f1a7b4eff8f8379ca5eed3f20b8c</anchor>
      <arglist>(CVC_CERT *a)</arglist>
    </member>
    <member kind="function">
      <type>CVC_CERT *</type>
      <name>d2i_CVC_CERT_bio</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga19aa7bd7c16a19d41536c674283d1457</anchor>
      <arglist>(BIO *bp, CVC_CERT **cvc)</arglist>
    </member>
    <member kind="function">
      <type>EVP_PKEY *</type>
      <name>CVC_pubkey2pkey</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga84dfe7c3da5df6756c92eeca501c87fe</anchor>
      <arglist>(const CVC_CERT *cert, BN_CTX *bn_ctx, EVP_PKEY *out)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>certificate_description_print</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga4d2388a9e59f0494a7fc8b8bf5cd5538</anchor>
      <arglist>(BIO *bio, const CVC_CERTIFICATE_DESCRIPTION *desc, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>cvc_chat_print</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga6cbe7fccc3b3c50761efc05f43a00c3a</anchor>
      <arglist>(BIO *bio, const CVC_CHAT *chat, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>cvc_chat_print_authorizations</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>gacdda7b257013c199ce6ff92793fa6767</anchor>
      <arglist>(BIO *bio, const CVC_CHAT *chat, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CVC_print</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga33515c2eb1aa44b1a85f7d9e9fa9c15e</anchor>
      <arglist>(BIO *bio, const CVC_CERT *cv, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>certificate_request_print</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga9e8c6ae74ee9d904c252fbb84842561e</anchor>
      <arglist>(BIO *bio, const CVC_CERT_REQUEST *request, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>certificate_authentication_request_print</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga24eac0cd08d21e122f93fe8e59f598e7</anchor>
      <arglist>(BIO *bio, const CVC_CERT_AUTHENTICATION_REQUEST *authentication, int indent)</arglist>
    </member>
    <member kind="function">
      <type>const CVC_CHAT *</type>
      <name>cvc_get_chat</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a604835f44c2197c1c9c7f8f8498e3112</anchor>
      <arglist>(const CVC_CERT *cvc)</arglist>
    </member>
    <member kind="function">
      <type>enum cvc_terminal_role</type>
      <name>CVC_get_role</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a5455c36dff717cd86b76e66e5745f26e</anchor>
      <arglist>(const CVC_CHAT *chat)</arglist>
    </member>
    <member kind="function">
      <type>short</type>
      <name>CVC_get_profile_identifier</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>ab7320b3c4d18c2a60eeca9fc6b64d974</anchor>
      <arglist>(const CVC_CERT *cert)</arglist>
    </member>
    <member kind="function">
      <type>char *</type>
      <name>CVC_get_car</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a74f1735bfd33173942bdfb997e2a2678</anchor>
      <arglist>(const CVC_CERT *cert)</arglist>
    </member>
    <member kind="function">
      <type>char *</type>
      <name>CVC_get_chr</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a9ab545b897f4f23279c2ba7189495e64</anchor>
      <arglist>(const CVC_CERT *cert)</arglist>
    </member>
    <member kind="function">
      <type>char *</type>
      <name>CVC_get_effective_date</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a2ff4c4e407f45866eaa658bb53b05514</anchor>
      <arglist>(const CVC_CERT *cert)</arglist>
    </member>
    <member kind="function">
      <type>char *</type>
      <name>CVC_get_expiration_date</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a20c200f0130936fab4501481cb119253</anchor>
      <arglist>(const CVC_CERT *cert)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CVC_verify_signature</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>aaba1e78aa4951f1ae9c5b777b3cff977</anchor>
      <arglist>(const CVC_CERT *cert, EVP_PKEY *key)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CVC_verify_request_signature</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a552794e00fda445f91610dad02ac5803</anchor>
      <arglist>(const CVC_CERT_REQUEST *request)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CVC_verify_authentication_request_signatures</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>aa2938141330b9c7096a0273b89bde955</anchor>
      <arglist>(struct eac_ctx *ctx, const CVC_CERT_AUTHENTICATION_REQUEST *authentication)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CVC_check_description</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>a6f758242008190302811e2249ce4125d</anchor>
      <arglist>(const CVC_CERT *cv, const unsigned char *cert_desc_in, const unsigned int cert_desc_in_len)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>CVC_hash_description</name>
      <anchorfile>cv__cert_8h.html</anchorfile>
      <anchor>ac3041c6df1ce54acce6adad2f2b20273</anchor>
      <arglist>(const CVC_CERT *cv, const unsigned char *cert_desc, size_t cert_desc_len)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>eac.h</name>
    <path>/home/fm/Dokumente/openpace/src/eac/</path>
    <filename>eac_8h</filename>
    <includes id="cv__cert_8h" name="cv_cert.h" local="no" imported="no">eac/cv_cert.h</includes>
    <includes id="objects_8h" name="objects.h" local="no" imported="no">eac/objects.h</includes>
    <class kind="struct">ka_ctx</class>
    <class kind="struct">pace_ctx</class>
    <class kind="struct">ri_ctx</class>
    <class kind="struct">ta_ctx</class>
    <class kind="struct">ca_ctx</class>
    <class kind="struct">eac_ctx</class>
    <member kind="define">
      <type>#define</type>
      <name>EAC_AES_MAC_LENGTH</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>ae91df2cf139e05110f5b3dae7f95bfe5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>EAC_ID_PACE</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga8e32964b13fe40c85d644478670ce4f3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>EAC_ID_CA</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga2c64f021a1496f58534fa6b7e15eb9a3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>EAC_ID_TA</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga2f47124dcb3bd045fc9b27db1321ebec</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>EAC_ID_EAC</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga3ac240a813e152822fed35fbdceacddf</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct ka_ctx</type>
      <name>KA_CTX</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>a4402d634a911197302d4e837028e3574</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct pace_ctx</type>
      <name>PACE_CTX</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>aa9e73c85f6dda35ca719f6e760f65f7a</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct ri_ctx</type>
      <name>RI_CTX</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>a5f9ef24d00954284d3dfb4988d89ccd5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>const CVC_CERT *(*</type>
      <name>CVC_lookup_cvca_cert</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>a8fd953d6eda2a6ef83e4ec23e065fa56</anchor>
      <arglist>)(const unsigned char *chr, size_t car_len)</arglist>
    </member>
    <member kind="typedef">
      <type>struct ta_ctx</type>
      <name>TA_CTX</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>a0ead002282275f60d3cd3afa173b3374</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>X509_STORE *(*</type>
      <name>X509_lookup_csca_cert</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>a14e6ca81c4faa924f26f58c7f76fd189</anchor>
      <arglist>)(unsigned long issuer_name_hash)</arglist>
    </member>
    <member kind="typedef">
      <type>struct ca_ctx</type>
      <name>CA_CTX</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>a8b43fdb0714ba4c6495c8dfe6c773b04</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct eac_ctx</type>
      <name>EAC_CTX</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>ae9b1b2593999b3c1b8eb10a4629b7c94</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>eac_tr_version</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>a1071d557ae2c818d130e7479c5f10dda</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>EAC_TR_VERSION</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>a1071d557ae2c818d130e7479c5f10ddaac61560d4c188f5be4670f235967e38d3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>EAC_TR_VERSION_2_01</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>a1071d557ae2c818d130e7479c5f10ddaa6216d6b5d2c9d4b0fea9aa9d8a176ec2</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>EAC_TR_VERSION_2_02</name>
      <anchorfile>eac_8h.html</anchorfile>
      <anchor>a1071d557ae2c818d130e7479c5f10ddaa8f9c82a9e23fc2501cdb91e5b53f2bb8</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>EAC_init</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga583066ccb6f5510b69fa278513927764</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>EAC_cleanup</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga6c56cc0f2481edc73bcdba4d5c79585a</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>EAC_CTX *</type>
      <name>EAC_CTX_new</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga193ce25ca9312d11f4f72810f961dd99</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>EAC_CTX_clear_free</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga6876daecd8aa07c88ed1af1e9df294d2</anchor>
      <arglist>(EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_init_pace</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga46f0c11c2cb763f166f8392bda3cd250</anchor>
      <arglist>(EAC_CTX *ctx, int protocol, int curve)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_init_ta</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga8f778cd8d31fa9657eab86eea947092a</anchor>
      <arglist>(const EAC_CTX *ctx, const unsigned char *privkey, size_t privkey_len, const unsigned char *cvca, size_t cvca_len)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_init_ca</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga7eac0f33848a850c1e5609d862e15546</anchor>
      <arglist>(EAC_CTX *ctx, int protocol, int curve)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_init_ri</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga13af3e1b70c708d99e81e4c7d3b0d750</anchor>
      <arglist>(EAC_CTX *ctx, int protocol, int stnd_dp)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_init_ef_cardaccess</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga8e67d2316561446a55256760afd9610e</anchor>
      <arglist>(unsigned const char *in, size_t in_len, EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_init_ef_cardsecurity</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gaa1eff489ae5f8d56d826c991893decac</anchor>
      <arglist>(const unsigned char *ef_cardsecurity, size_t ef_cardsecurity_len, EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_get_cvca_lookup_cert</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gaabd3c88e09a47c2513d6c68c0bed7479</anchor>
      <arglist>(const EAC_CTX *ctx, CVC_lookup_cvca_cert *lookup_cvca_cert)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_set_cvca_lookup_cert</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gad5e131a9130b00ff9e589cd365736e71</anchor>
      <arglist>(EAC_CTX *ctx, CVC_lookup_cvca_cert lookup_cvca_cert)</arglist>
    </member>
    <member kind="function">
      <type>CVC_lookup_cvca_cert</type>
      <name>EAC_get_default_cvca_lookup</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga842d902f8c9ce5d7ecdc83c2940c313b</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>EAC_set_cvc_default_dir</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga6ea1d637fd78de052fff7a048a25aafb</anchor>
      <arglist>(const char *default_dir)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_get_csca_lookup_cert</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga063457a7d04d05cf437f0b6bd3cc1367</anchor>
      <arglist>(const EAC_CTX *ctx, X509_lookup_csca_cert *lookup_cvca_cert)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_set_csca_lookup_cert</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga528afab99e4eeb222fcc6b4edc46139e</anchor>
      <arglist>(EAC_CTX *ctx, X509_lookup_csca_cert lookup_cvca_cert)</arglist>
    </member>
    <member kind="function">
      <type>X509_lookup_csca_cert</type>
      <name>EAC_get_default_csca_lookup</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga2603a5a963d5d95cce3cc76ea470d794</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>EAC_set_x509_default_dir</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga595722cf2af1e61aaaa67a6ff23dcaad</anchor>
      <arglist>(const char *default_dir)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_add_iso_pad</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga9e1039cf926ca0964f430ec4f0438eb3</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *unpadded)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_remove_iso_pad</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga2d8e5441271c5fc9b93b4786325211a4</anchor>
      <arglist>(const BUF_MEM *padded)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_increment_ssc</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>gae19014262be52d19ad563c9c5e16ffcf</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_reset_ssc</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga6e5edec29e781d9d665fcf160b2093e3</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_set_ssc</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>gacc8beba0a4e3ae9448ea3256cb5e4341</anchor>
      <arglist>(const EAC_CTX *ctx, unsigned long ssc)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_encrypt</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga56be34fb57fd13db3be27161c21ecccc</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *data)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_decrypt</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga0582a6acf2cc8c435f9bf54f0b750258</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *data)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_authenticate</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga81da2809a9490aa81825e2f3257d08ae</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *data)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_verify_authentication</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga50467cdf67ae44a53f86a583fc19797d</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *data, const BUF_MEM *mac)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_Comp</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>gab211f297f88ae57ce11588f8754c9c8c</anchor>
      <arglist>(const EAC_CTX *ctx, int id, const BUF_MEM *pub)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_hash_certificate_description</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga9ebe2d91e1c9270c7d13443100fcd524</anchor>
      <arglist>(const unsigned char *cert_desc, size_t cert_desc_len)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_set_encryption_ctx</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga5df516d484102e4315a1712be8f8a656</anchor>
      <arglist>(EAC_CTX *ctx, int id)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_print_private</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga69dfa847f834d5cfa559a88ceb8d04c8</anchor>
      <arglist>(BIO *out, const EAC_CTX *ctx, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>BUF_MEM_print</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga7bd156b63fc10e59fddb4d9fbe6f2f5c</anchor>
      <arglist>(BIO *out, const BUF_MEM *buf, int indent)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>BUF_MEM_clear_free</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga2ed7b3ca7230dc0d6f66e64a72257ff2</anchor>
      <arglist>(BUF_MEM *b)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>objects.h</name>
    <path>/home/fm/Dokumente/openpace/src/eac/</path>
    <filename>objects_8h</filename>
  </compound>
  <compound kind="file">
    <name>pace.h</name>
    <path>/home/fm/Dokumente/openpace/src/eac/</path>
    <filename>pace_8h</filename>
    <includes id="eac_8h" name="eac.h" local="yes" imported="no">eac.h</includes>
    <class kind="struct">pace_sec</class>
    <member kind="typedef">
      <type>struct pace_sec</type>
      <name>PACE_SEC</name>
      <anchorfile>pace_8h.html</anchorfile>
      <anchor>a4077e81a0fc6bf763716d0a578e7f46f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>s_type</name>
      <anchorfile>pace_8h.html</anchorfile>
      <anchor>a02b29cbcf45cfaa2e6df0f59b98b3525</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>PACE_MRZ</name>
      <anchorfile>pace_8h.html</anchorfile>
      <anchor>a02b29cbcf45cfaa2e6df0f59b98b3525a1c7152d3c1a0b7e8543cbf176e38d8f2</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>PACE_CAN</name>
      <anchorfile>pace_8h.html</anchorfile>
      <anchor>a02b29cbcf45cfaa2e6df0f59b98b3525afbbe0ce2ae202cc1837422a10ce487a1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>PACE_PIN</name>
      <anchorfile>pace_8h.html</anchorfile>
      <anchor>a02b29cbcf45cfaa2e6df0f59b98b3525aaf59d2b47ca6bd89c0db0579bc2ede28</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>PACE_PUK</name>
      <anchorfile>pace_8h.html</anchorfile>
      <anchor>a02b29cbcf45cfaa2e6df0f59b98b3525a4416853caf39bcbb2a967ba2558d3805</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>PACE_RAW</name>
      <anchorfile>pace_8h.html</anchorfile>
      <anchor>a02b29cbcf45cfaa2e6df0f59b98b3525abc55b260a6cc5bdcea0fd496cb847fc4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <type>@</type>
      <name>PACE_SEC_UNDEF</name>
      <anchorfile>pace_8h.html</anchorfile>
      <anchor>a02b29cbcf45cfaa2e6df0f59b98b3525aa771208f20a5aacab35ddb611ecac21b</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>PACE_SEC_clear_free</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga434cf93529804c711640461a3930f576</anchor>
      <arglist>(PACE_SEC *s)</arglist>
    </member>
    <member kind="function">
      <type>PACE_SEC *</type>
      <name>PACE_SEC_new</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gae35799ea82f5af5420ed100da61fde71</anchor>
      <arglist>(const char *sec, size_t sec_len, enum s_type type)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>PACE_SEC_print_private</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga7a3bae35256a5d00c765d4bc60e2c833</anchor>
      <arglist>(BIO *out, const PACE_SEC *sec, int indent)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>PACE_STEP1_enc_nonce</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>ga275e2d1f7e8cd77f2448ad4fbd09984f</anchor>
      <arglist>(const EAC_CTX *ctx, const PACE_SEC *pi)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>PACE_STEP2_dec_nonce</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>gaa46fbd637f3bf063b5c68f37d40efba3</anchor>
      <arglist>(const EAC_CTX *ctx, const PACE_SEC *pi, const BUF_MEM *enc_nonce)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>PACE_STEP3A_generate_mapping_data</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>gafd890198805ed2591f172e7815b8a2df</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>PACE_STEP3A_map_generator</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>ga56c295adbcbca57a6059c04a480d9ff7</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *in)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>PACE_STEP3B_generate_ephemeral_key</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>gafcb6f32a13e38cb23a82e33faa817179</anchor>
      <arglist>(EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>PACE_STEP3B_compute_shared_secret</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>gaee1105d7cbd1fe8629157a3b97f25c52</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *in)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>PACE_STEP3C_derive_keys</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>gae3a44c7269e95f48874dd909ed34ba77</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>PACE_STEP3D_compute_authentication_token</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>gaf682c5881e60755ef23e4e583e4d7cdd</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *pub)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>PACE_STEP3D_verify_authentication_token</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>ga424f7f098e8377ea602c4f5233a04f3d</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *token)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>ri.h</name>
    <path>/home/fm/Dokumente/openpace/src/eac/</path>
    <filename>ri_8h</filename>
    <includes id="eac_8h" name="eac.h" local="no" imported="no">eac/eac.h</includes>
    <member kind="function">
      <type>void</type>
      <name>RI_CTX_clear_free</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga3f50a8cffdf5aab322e37dafc6763ef7</anchor>
      <arglist>(RI_CTX *s)</arglist>
    </member>
    <member kind="function">
      <type>RI_CTX *</type>
      <name>RI_CTX_new</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gac0bf8ff4cfd00ed06afceaf89c10aa3e</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>RI_CTX_set_protocol</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gabeaf41c7c78859490c52308196c1aa66</anchor>
      <arglist>(RI_CTX *ctx, int protocol)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>RI_STEP2_compute_identifier</name>
      <anchorfile>group__riproto.html</anchorfile>
      <anchor>ga93bccb469abf0a6070b839b099505e96</anchor>
      <arglist>(EAC_CTX *ctx, BUF_MEM *sector_pubkey)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>ta.h</name>
    <path>/home/fm/Dokumente/openpace/src/eac/</path>
    <filename>ta_8h</filename>
    <includes id="eac_8h" name="eac.h" local="no" imported="no">eac/eac.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>TA_FLAG_SKIP_TIMECHECK</name>
      <anchorfile>ta_8h.html</anchorfile>
      <anchor>ab828df94adf4d17cd35281c676bb45d0</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>TA_disable_checks</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga3b9f3dfea8560bd63e9594d32994bd95</anchor>
      <arglist>(EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>TA_STEP2_import_certificate</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga042883976e7a3423db2f99f6501272a7</anchor>
      <arglist>(const EAC_CTX *ctx, const unsigned char *cert, size_t cert_len)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>TA_STEP3_generate_ephemeral_key</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga1d7bcb63f5a375759d9d040c200068c3</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>TA_STEP4_get_nonce</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga1a4d4534bb23c4d2ffefb5bfdec335ff</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>TA_STEP4_set_nonce</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga65d4a5c270c5071b7bc7bce3ab189cda</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *nonce)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>TA_STEP5_sign</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga31712e0ebf291f0f31cd462f33a0d802</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *my_ta_eph_pubkey, const BUF_MEM *opp_pace_eph_pubkey, const BUF_MEM *auxdata)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>TA_STEP6_verify</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga76fe96c3ba3d1ed684f08e8d486d2f2b</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *opp_ta_comp_eph_pubkey, const BUF_MEM *my_pace_comp_eph_pubkey, const BUF_MEM *auxdata, const BUF_MEM *signature)</arglist>
    </member>
  </compound>
  <compound kind="group">
    <name>management</name>
    <title>Data Management and Initialization</title>
    <filename>group__management.html</filename>
    <member kind="define">
      <type>#define</type>
      <name>CVC_CERT_dup</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gaf8df0122e9d69243120b62033c4b9474</anchor>
      <arglist>(x)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>CVC_PUBKEY_dup</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga3c3f5a64d45ed99d9c5cfd0a0c61b869</anchor>
      <arglist>(x)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>CVC_CHAT_dup</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gadf010f3a63a21336d1025a3f7814c322</anchor>
      <arglist>(x)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>CA_disable_passive_authentication</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga28c1d11845924a1cd08461c6a1a765cc</anchor>
      <arglist>(EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>CVC_CERT *</type>
      <name>CVC_d2i_CVC_CERT</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga59de291be2953ebf60bce12225fed74f</anchor>
      <arglist>(CVC_CERT **cert, const unsigned char **in, long len)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>i2d_CVC_CERT</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga63dd3f2ebdc39d4a9e0b0af8d12ec655</anchor>
      <arglist>(CVC_CERT *a, unsigned char **out)</arglist>
    </member>
    <member kind="function">
      <type>CVC_CERT *</type>
      <name>CVC_CERT_new</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga90b0e7ddb7b193cbc414f8d88cd9e6cc</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>CVC_CERT_free</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga24e6f1a7b4eff8f8379ca5eed3f20b8c</anchor>
      <arglist>(CVC_CERT *a)</arglist>
    </member>
    <member kind="function">
      <type>CVC_CERT *</type>
      <name>d2i_CVC_CERT_bio</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga19aa7bd7c16a19d41536c674283d1457</anchor>
      <arglist>(BIO *bp, CVC_CERT **cvc)</arglist>
    </member>
    <member kind="function">
      <type>EVP_PKEY *</type>
      <name>CVC_pubkey2pkey</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga84dfe7c3da5df6756c92eeca501c87fe</anchor>
      <arglist>(const CVC_CERT *cert, BN_CTX *bn_ctx, EVP_PKEY *out)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>EAC_init</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga583066ccb6f5510b69fa278513927764</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>EAC_cleanup</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga6c56cc0f2481edc73bcdba4d5c79585a</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>EAC_CTX *</type>
      <name>EAC_CTX_new</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga193ce25ca9312d11f4f72810f961dd99</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>EAC_CTX_clear_free</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga6876daecd8aa07c88ed1af1e9df294d2</anchor>
      <arglist>(EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_init_pace</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga46f0c11c2cb763f166f8392bda3cd250</anchor>
      <arglist>(EAC_CTX *ctx, int protocol, int curve)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_init_ta</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga8f778cd8d31fa9657eab86eea947092a</anchor>
      <arglist>(const EAC_CTX *ctx, const unsigned char *privkey, size_t privkey_len, const unsigned char *cvca, size_t cvca_len)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_init_ca</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga7eac0f33848a850c1e5609d862e15546</anchor>
      <arglist>(EAC_CTX *ctx, int protocol, int curve)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_init_ri</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga13af3e1b70c708d99e81e4c7d3b0d750</anchor>
      <arglist>(EAC_CTX *ctx, int protocol, int stnd_dp)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_init_ef_cardaccess</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga8e67d2316561446a55256760afd9610e</anchor>
      <arglist>(unsigned const char *in, size_t in_len, EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_init_ef_cardsecurity</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gaa1eff489ae5f8d56d826c991893decac</anchor>
      <arglist>(const unsigned char *ef_cardsecurity, size_t ef_cardsecurity_len, EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_get_cvca_lookup_cert</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gaabd3c88e09a47c2513d6c68c0bed7479</anchor>
      <arglist>(const EAC_CTX *ctx, CVC_lookup_cvca_cert *lookup_cvca_cert)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_set_cvca_lookup_cert</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gad5e131a9130b00ff9e589cd365736e71</anchor>
      <arglist>(EAC_CTX *ctx, CVC_lookup_cvca_cert lookup_cvca_cert)</arglist>
    </member>
    <member kind="function">
      <type>CVC_lookup_cvca_cert</type>
      <name>EAC_get_default_cvca_lookup</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga842d902f8c9ce5d7ecdc83c2940c313b</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>EAC_set_cvc_default_dir</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga6ea1d637fd78de052fff7a048a25aafb</anchor>
      <arglist>(const char *default_dir)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_get_csca_lookup_cert</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga063457a7d04d05cf437f0b6bd3cc1367</anchor>
      <arglist>(const EAC_CTX *ctx, X509_lookup_csca_cert *lookup_cvca_cert)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_set_csca_lookup_cert</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga528afab99e4eeb222fcc6b4edc46139e</anchor>
      <arglist>(EAC_CTX *ctx, X509_lookup_csca_cert lookup_cvca_cert)</arglist>
    </member>
    <member kind="function">
      <type>X509_lookup_csca_cert</type>
      <name>EAC_get_default_csca_lookup</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga2603a5a963d5d95cce3cc76ea470d794</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>EAC_set_x509_default_dir</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga595722cf2af1e61aaaa67a6ff23dcaad</anchor>
      <arglist>(const char *default_dir)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>PACE_SEC_clear_free</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga434cf93529804c711640461a3930f576</anchor>
      <arglist>(PACE_SEC *s)</arglist>
    </member>
    <member kind="function">
      <type>PACE_SEC *</type>
      <name>PACE_SEC_new</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gae35799ea82f5af5420ed100da61fde71</anchor>
      <arglist>(const char *sec, size_t sec_len, enum s_type type)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>PACE_SEC_print_private</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga7a3bae35256a5d00c765d4bc60e2c833</anchor>
      <arglist>(BIO *out, const PACE_SEC *sec, int indent)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>RI_CTX_clear_free</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>ga3f50a8cffdf5aab322e37dafc6763ef7</anchor>
      <arglist>(RI_CTX *s)</arglist>
    </member>
    <member kind="function">
      <type>RI_CTX *</type>
      <name>RI_CTX_new</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gac0bf8ff4cfd00ed06afceaf89c10aa3e</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>RI_CTX_set_protocol</name>
      <anchorfile>group__management.html</anchorfile>
      <anchor>gabeaf41c7c78859490c52308196c1aa66</anchor>
      <arglist>(RI_CTX *ctx, int protocol)</arglist>
    </member>
  </compound>
  <compound kind="group">
    <name>printing</name>
    <title>Data Printing</title>
    <filename>group__printing.html</filename>
    <member kind="function">
      <type>int</type>
      <name>certificate_description_print</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga4d2388a9e59f0494a7fc8b8bf5cd5538</anchor>
      <arglist>(BIO *bio, const CVC_CERTIFICATE_DESCRIPTION *desc, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>cvc_chat_print</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga6cbe7fccc3b3c50761efc05f43a00c3a</anchor>
      <arglist>(BIO *bio, const CVC_CHAT *chat, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>cvc_chat_print_authorizations</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>gacdda7b257013c199ce6ff92793fa6767</anchor>
      <arglist>(BIO *bio, const CVC_CHAT *chat, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CVC_print</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga33515c2eb1aa44b1a85f7d9e9fa9c15e</anchor>
      <arglist>(BIO *bio, const CVC_CERT *cv, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>certificate_request_print</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga9e8c6ae74ee9d904c252fbb84842561e</anchor>
      <arglist>(BIO *bio, const CVC_CERT_REQUEST *request, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>certificate_authentication_request_print</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga24eac0cd08d21e122f93fe8e59f598e7</anchor>
      <arglist>(BIO *bio, const CVC_CERT_AUTHENTICATION_REQUEST *authentication, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_print_private</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga69dfa847f834d5cfa559a88ceb8d04c8</anchor>
      <arglist>(BIO *out, const EAC_CTX *ctx, int indent)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>BUF_MEM_print</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga7bd156b63fc10e59fddb4d9fbe6f2f5c</anchor>
      <arglist>(BIO *out, const BUF_MEM *buf, int indent)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>BUF_MEM_clear_free</name>
      <anchorfile>group__printing.html</anchorfile>
      <anchor>ga2ed7b3ca7230dc0d6f66e64a72257ff2</anchor>
      <arglist>(BUF_MEM *b)</arglist>
    </member>
  </compound>
  <compound kind="group">
    <name>eacproto</name>
    <title>Protocol Steps for Extended Access Control</title>
    <filename>group__eacproto.html</filename>
    <subgroup>paceproto</subgroup>
    <subgroup>taproto</subgroup>
    <subgroup>caproto</subgroup>
    <subgroup>riproto</subgroup>
  </compound>
  <compound kind="group">
    <name>paceproto</name>
    <title>Protocol Steps for Password Authenticated Connection Establishment</title>
    <filename>group__paceproto.html</filename>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>PACE_STEP1_enc_nonce</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>ga275e2d1f7e8cd77f2448ad4fbd09984f</anchor>
      <arglist>(const EAC_CTX *ctx, const PACE_SEC *pi)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>PACE_STEP2_dec_nonce</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>gaa46fbd637f3bf063b5c68f37d40efba3</anchor>
      <arglist>(const EAC_CTX *ctx, const PACE_SEC *pi, const BUF_MEM *enc_nonce)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>PACE_STEP3A_generate_mapping_data</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>gafd890198805ed2591f172e7815b8a2df</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>PACE_STEP3A_map_generator</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>ga56c295adbcbca57a6059c04a480d9ff7</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *in)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>PACE_STEP3B_generate_ephemeral_key</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>gafcb6f32a13e38cb23a82e33faa817179</anchor>
      <arglist>(EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>PACE_STEP3B_compute_shared_secret</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>gaee1105d7cbd1fe8629157a3b97f25c52</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *in)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>PACE_STEP3C_derive_keys</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>gae3a44c7269e95f48874dd909ed34ba77</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>PACE_STEP3D_compute_authentication_token</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>gaf682c5881e60755ef23e4e583e4d7cdd</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *pub)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>PACE_STEP3D_verify_authentication_token</name>
      <anchorfile>group__paceproto.html</anchorfile>
      <anchor>ga424f7f098e8377ea602c4f5233a04f3d</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *token)</arglist>
    </member>
  </compound>
  <compound kind="group">
    <name>taproto</name>
    <title>Protocol Steps for Terminal Authentication</title>
    <filename>group__taproto.html</filename>
    <member kind="function">
      <type>void</type>
      <name>TA_disable_checks</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga3b9f3dfea8560bd63e9594d32994bd95</anchor>
      <arglist>(EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>TA_STEP2_import_certificate</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga042883976e7a3423db2f99f6501272a7</anchor>
      <arglist>(const EAC_CTX *ctx, const unsigned char *cert, size_t cert_len)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>TA_STEP3_generate_ephemeral_key</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga1d7bcb63f5a375759d9d040c200068c3</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>TA_STEP4_get_nonce</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga1a4d4534bb23c4d2ffefb5bfdec335ff</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>TA_STEP4_set_nonce</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga65d4a5c270c5071b7bc7bce3ab189cda</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *nonce)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>TA_STEP5_sign</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga31712e0ebf291f0f31cd462f33a0d802</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *my_ta_eph_pubkey, const BUF_MEM *opp_pace_eph_pubkey, const BUF_MEM *auxdata)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>TA_STEP6_verify</name>
      <anchorfile>group__taproto.html</anchorfile>
      <anchor>ga76fe96c3ba3d1ed684f08e8d486d2f2b</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *opp_ta_comp_eph_pubkey, const BUF_MEM *my_pace_comp_eph_pubkey, const BUF_MEM *auxdata, const BUF_MEM *signature)</arglist>
    </member>
  </compound>
  <compound kind="group">
    <name>caproto</name>
    <title>Protocol Steps for Chip Authentication</title>
    <filename>group__caproto.html</filename>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>CA_STEP1_get_pubkey</name>
      <anchorfile>group__caproto.html</anchorfile>
      <anchor>gafdf162f33faea84cb7ff359bb1d5c09d</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>CA_STEP2_get_eph_pubkey</name>
      <anchorfile>group__caproto.html</anchorfile>
      <anchor>gad2aaec726b132e27f50aaa16bfbde574</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CA_STEP3_check_pcd_pubkey</name>
      <anchorfile>group__caproto.html</anchorfile>
      <anchor>ga6f5f7dfc8323a946fec506956018525a</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *comp_pubkey, const BUF_MEM *pubkey)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CA_STEP4_compute_shared_secret</name>
      <anchorfile>group__caproto.html</anchorfile>
      <anchor>ga5ebe4465cab901c4bb94a75c74bf71fa</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *pubkey)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CA_STEP5_derive_keys</name>
      <anchorfile>group__caproto.html</anchorfile>
      <anchor>ga37bfdcc37ae95d411b5919cdd02fa3bf</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *pub, BUF_MEM **nonce, BUF_MEM **token)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>CA_STEP6_derive_keys</name>
      <anchorfile>group__caproto.html</anchorfile>
      <anchor>ga34352b58c89ce58c4e3e425bfb20ef45</anchor>
      <arglist>(EAC_CTX *ctx, const BUF_MEM *nonce, const BUF_MEM *token)</arglist>
    </member>
  </compound>
  <compound kind="group">
    <name>riproto</name>
    <title>Protocol Steps for Restricted Authentication</title>
    <filename>group__riproto.html</filename>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>RI_STEP2_compute_identifier</name>
      <anchorfile>group__riproto.html</anchorfile>
      <anchor>ga93bccb469abf0a6070b839b099505e96</anchor>
      <arglist>(EAC_CTX *ctx, BUF_MEM *sector_pubkey)</arglist>
    </member>
  </compound>
  <compound kind="group">
    <name>sm</name>
    <title>Cryptographic Wrappers for Secure Messaging</title>
    <filename>group__sm.html</filename>
    <member kind="define">
      <type>#define</type>
      <name>EAC_ID_PACE</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga8e32964b13fe40c85d644478670ce4f3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>EAC_ID_CA</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga2c64f021a1496f58534fa6b7e15eb9a3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>EAC_ID_TA</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga2f47124dcb3bd045fc9b27db1321ebec</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>EAC_ID_EAC</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga3ac240a813e152822fed35fbdceacddf</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_add_iso_pad</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga9e1039cf926ca0964f430ec4f0438eb3</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *unpadded)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_remove_iso_pad</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga2d8e5441271c5fc9b93b4786325211a4</anchor>
      <arglist>(const BUF_MEM *padded)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_increment_ssc</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>gae19014262be52d19ad563c9c5e16ffcf</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_reset_ssc</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga6e5edec29e781d9d665fcf160b2093e3</anchor>
      <arglist>(const EAC_CTX *ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_set_ssc</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>gacc8beba0a4e3ae9448ea3256cb5e4341</anchor>
      <arglist>(const EAC_CTX *ctx, unsigned long ssc)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_encrypt</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga56be34fb57fd13db3be27161c21ecccc</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *data)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_decrypt</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga0582a6acf2cc8c435f9bf54f0b750258</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *data)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_authenticate</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga81da2809a9490aa81825e2f3257d08ae</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *data)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_verify_authentication</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga50467cdf67ae44a53f86a583fc19797d</anchor>
      <arglist>(const EAC_CTX *ctx, const BUF_MEM *data, const BUF_MEM *mac)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_Comp</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>gab211f297f88ae57ce11588f8754c9c8c</anchor>
      <arglist>(const EAC_CTX *ctx, int id, const BUF_MEM *pub)</arglist>
    </member>
    <member kind="function">
      <type>BUF_MEM *</type>
      <name>EAC_hash_certificate_description</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga9ebe2d91e1c9270c7d13443100fcd524</anchor>
      <arglist>(const unsigned char *cert_desc, size_t cert_desc_len)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>EAC_CTX_set_encryption_ctx</name>
      <anchorfile>group__sm.html</anchorfile>
      <anchor>ga5df516d484102e4315a1712be8f8a656</anchor>
      <arglist>(EAC_CTX *ctx, int id)</arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>ca_ctx</name>
    <filename>structca__ctx.html</filename>
    <member kind="variable">
      <type>unsigned char</type>
      <name>version</name>
      <anchorfile>structca__ctx.html</anchorfile>
      <anchor>a01f3b87f0a1c8db086aeecb359e22f81</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>protocol</name>
      <anchorfile>structca__ctx.html</anchorfile>
      <anchor>a9322acf2acaef458196c3b26e42993d2</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>id</name>
      <anchorfile>structca__ctx.html</anchorfile>
      <anchor>a0f1a30c4b0548cdb0920e928351964d6</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>flags</name>
      <anchorfile>structca__ctx.html</anchorfile>
      <anchor>a4b00f374e7f43c90c6799276feb2cf2a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>KA_CTX *</type>
      <name>ka_ctx</name>
      <anchorfile>structca__ctx.html</anchorfile>
      <anchor>ad869c8e99104ace4478a9f5b52a51abc</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>X509_lookup_csca_cert</type>
      <name>lookup_csca_cert</name>
      <anchorfile>structca__ctx.html</anchorfile>
      <anchor>ac2999e422c563a94a34746cd2afca8bb</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>cvc_cert_authentication_request_seq_st</name>
    <filename>structcvc__cert__authentication__request__seq__st.html</filename>
    <member kind="variable">
      <type>CVC_CERT_REQUEST *</type>
      <name>request</name>
      <anchorfile>structcvc__cert__authentication__request__seq__st.html</anchorfile>
      <anchor>a141aafcff6a4a219520e8be13f1a0a08</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_UTF8STRING *</type>
      <name>certificate_authority_reference</name>
      <anchorfile>structcvc__cert__authentication__request__seq__st.html</anchorfile>
      <anchor>ad1e127ab86b2f67e3d9d099a18edb150</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>outer_signature</name>
      <anchorfile>structcvc__cert__authentication__request__seq__st.html</anchorfile>
      <anchor>ade1fb2b0d00e59d224bc9436ff59935b</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>cvc_cert_body_seq_st</name>
    <filename>structcvc__cert__body__seq__st.html</filename>
    <member kind="function">
      <type></type>
      <name>STACK_OF</name>
      <anchorfile>structcvc__cert__body__seq__st.html</anchorfile>
      <anchor>aa4b3f524d766b4bfdae878faa6dee5b7</anchor>
      <arglist>(CVC_DISCRETIONARY_DATA_TEMPLATE)*certificate_extensions</arglist>
    </member>
    <member kind="variable">
      <type>ASN1_INTEGER *</type>
      <name>certificate_profile_identifier</name>
      <anchorfile>structcvc__cert__body__seq__st.html</anchorfile>
      <anchor>a225ab4fd481f97ef1c5b4ce84b62cfb1</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_UTF8STRING *</type>
      <name>certificate_authority_reference</name>
      <anchorfile>structcvc__cert__body__seq__st.html</anchorfile>
      <anchor>ac15201a6078ac2ed976019148c65245a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>CVC_PUBKEY *</type>
      <name>public_key</name>
      <anchorfile>structcvc__cert__body__seq__st.html</anchorfile>
      <anchor>a47a11738c575d5b46499a4efda852c72</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_UTF8STRING *</type>
      <name>certificate_holder_reference</name>
      <anchorfile>structcvc__cert__body__seq__st.html</anchorfile>
      <anchor>a2f3ea562a965817ac5c64a8f3c935014</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>CVC_CHAT *</type>
      <name>chat</name>
      <anchorfile>structcvc__cert__body__seq__st.html</anchorfile>
      <anchor>a1f2a4144cdcae0a93da53c59fbd7eb41</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>certificate_effective_date</name>
      <anchorfile>structcvc__cert__body__seq__st.html</anchorfile>
      <anchor>a18649711fa50b4740d406bb3dc6c8b63</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>certificate_expiration_date</name>
      <anchorfile>structcvc__cert__body__seq__st.html</anchorfile>
      <anchor>a74a9b55ba3d5b1f5773372d95cec9dda</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>cvc_cert_request_body_seq_st</name>
    <filename>structcvc__cert__request__body__seq__st.html</filename>
    <member kind="function">
      <type></type>
      <name>STACK_OF</name>
      <anchorfile>structcvc__cert__request__body__seq__st.html</anchorfile>
      <anchor>ae3f7e3b87885ba742acaad8af6fbcfc7</anchor>
      <arglist>(CVC_DISCRETIONARY_DATA_TEMPLATE)*certificate_extensions</arglist>
    </member>
    <member kind="variable">
      <type>ASN1_INTEGER *</type>
      <name>certificate_profile_identifier</name>
      <anchorfile>structcvc__cert__request__body__seq__st.html</anchorfile>
      <anchor>a637aeb87e207fc7075e144290591bfe2</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_UTF8STRING *</type>
      <name>certificate_authority_reference</name>
      <anchorfile>structcvc__cert__request__body__seq__st.html</anchorfile>
      <anchor>a600a809bd24cf1461353c31c944acf7a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>CVC_PUBKEY *</type>
      <name>public_key</name>
      <anchorfile>structcvc__cert__request__body__seq__st.html</anchorfile>
      <anchor>a9c139e9e28e62f8e65d1f67289a11004</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_UTF8STRING *</type>
      <name>certificate_holder_reference</name>
      <anchorfile>structcvc__cert__request__body__seq__st.html</anchorfile>
      <anchor>ae1d0a6791c93906d6ec0da99dcc3f095</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>cvc_cert_request_seq_st</name>
    <filename>structcvc__cert__request__seq__st.html</filename>
    <member kind="variable">
      <type>CVC_CERT_REQUEST_BODY *</type>
      <name>body</name>
      <anchorfile>structcvc__cert__request__seq__st.html</anchorfile>
      <anchor>a5301cbf633d82b8b0526135195be32ba</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>inner_signature</name>
      <anchorfile>structcvc__cert__request__seq__st.html</anchorfile>
      <anchor>a78f3ce89184e9af12145271bd448691f</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>cvc_cert_seq_st</name>
    <filename>structcvc__cert__seq__st.html</filename>
    <member kind="variable">
      <type>CVC_CERT_BODY *</type>
      <name>body</name>
      <anchorfile>structcvc__cert__seq__st.html</anchorfile>
      <anchor>a590a84f99e3ba059e4e5a9d76e58860e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>signature</name>
      <anchorfile>structcvc__cert__seq__st.html</anchorfile>
      <anchor>a1d06dc06fc61171b080c49a21514ab00</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>cvc_certificate_description_st</name>
    <filename>structcvc__certificate__description__st.html</filename>
    <member kind="variable">
      <type>ASN1_OBJECT *</type>
      <name>descriptionType</name>
      <anchorfile>structcvc__certificate__description__st.html</anchorfile>
      <anchor>a77a981adef7b7b18d7d2fc0dcf0d0eee</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_UTF8STRING *</type>
      <name>issuerName</name>
      <anchorfile>structcvc__certificate__description__st.html</anchorfile>
      <anchor>aff81a8239e606700ba5cb5d3e9e88dc9</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_PRINTABLESTRING *</type>
      <name>issuerURL</name>
      <anchorfile>structcvc__certificate__description__st.html</anchorfile>
      <anchor>ae07239454cef11745b9d44ce11c04eb4</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_UTF8STRING *</type>
      <name>subjectName</name>
      <anchorfile>structcvc__certificate__description__st.html</anchorfile>
      <anchor>ac1be45c1e8ccdbd97486419573586013</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_PRINTABLESTRING *</type>
      <name>subjectURL</name>
      <anchorfile>structcvc__certificate__description__st.html</anchorfile>
      <anchor>a93c4e5528d00e394b001160000f0c537</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>union cvc_certificate_description_st::@0</type>
      <name>termsOfUsage</name>
      <anchorfile>structcvc__certificate__description__st.html</anchorfile>
      <anchor>a0d3dd884537299633d2865130d44cc5b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_PRINTABLESTRING *</type>
      <name>redirectURL</name>
      <anchorfile>structcvc__certificate__description__st.html</anchorfile>
      <anchor>a89df677bee1e9180d083d626785bcf4a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>CVC_COMMCERT_SEQ *</type>
      <name>commCertificates</name>
      <anchorfile>structcvc__certificate__description__st.html</anchorfile>
      <anchor>ad89163e798fec8f4b9acef7f6c149755</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>cvc_chat_seq_st</name>
    <filename>structcvc__chat__seq__st.html</filename>
    <member kind="variable">
      <type>ASN1_OBJECT *</type>
      <name>terminal_type</name>
      <anchorfile>structcvc__chat__seq__st.html</anchorfile>
      <anchor>ad256b27e8fb8c4390412f175b8630559</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>relative_authorization</name>
      <anchorfile>structcvc__chat__seq__st.html</anchorfile>
      <anchor>a7e750c5f8434462ea05c8602ad672011</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>cvc_commcert_seq_st</name>
    <filename>structcvc__commcert__seq__st.html</filename>
    <member kind="function">
      <type></type>
      <name>STACK_OF</name>
      <anchorfile>structcvc__commcert__seq__st.html</anchorfile>
      <anchor>a52f90146d3ac5aa2cb2936f107e41d87</anchor>
      <arglist>(ASN1_OCTET_STRING)*values</arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>cvc_discretionary_data_template_seq_st</name>
    <filename>structcvc__discretionary__data__template__seq__st.html</filename>
    <member kind="variable">
      <type>ASN1_OBJECT *</type>
      <name>type</name>
      <anchorfile>structcvc__discretionary__data__template__seq__st.html</anchorfile>
      <anchor>a28bc2f1d46e8feb5ad202b25903f809d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>discretionary_data1</name>
      <anchorfile>structcvc__discretionary__data__template__seq__st.html</anchorfile>
      <anchor>a658a921185a7e04cc0b934b357f4b466</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>discretionary_data2</name>
      <anchorfile>structcvc__discretionary__data__template__seq__st.html</anchorfile>
      <anchor>a839b632118440ca294586fd82a041ae2</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>discretionary_data3</name>
      <anchorfile>structcvc__discretionary__data__template__seq__st.html</anchorfile>
      <anchor>a07b6e574f47de38cf02fa8ab77ab2384</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>cvc_pubkey_st</name>
    <filename>structcvc__pubkey__st.html</filename>
    <member kind="variable">
      <type>ASN1_OBJECT *</type>
      <name>oid</name>
      <anchorfile>structcvc__pubkey__st.html</anchorfile>
      <anchor>a4d257366c407b3b031ffe1dc2ea97ce5</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>cont1</name>
      <anchorfile>structcvc__pubkey__st.html</anchorfile>
      <anchor>af1146b162c5ac3116d7c38d7519ebe29</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>cont2</name>
      <anchorfile>structcvc__pubkey__st.html</anchorfile>
      <anchor>a9e3f2ee8ffead450717d46fd481bfa2f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>cont3</name>
      <anchorfile>structcvc__pubkey__st.html</anchorfile>
      <anchor>ab83ac437168fc16aaa41c7a0b9522395</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>cont4</name>
      <anchorfile>structcvc__pubkey__st.html</anchorfile>
      <anchor>ad58be5d0a1fbdc86325187d87a0ec7aa</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>cont5</name>
      <anchorfile>structcvc__pubkey__st.html</anchorfile>
      <anchor>aab4bae046882a2dd7b543def58fee35c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>cont6</name>
      <anchorfile>structcvc__pubkey__st.html</anchorfile>
      <anchor>a1f6427049f50dc10bd720b756fa8dd8d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ASN1_OCTET_STRING *</type>
      <name>cont7</name>
      <anchorfile>structcvc__pubkey__st.html</anchorfile>
      <anchor>ace297c25e80edbc78986c1e63ddc363b</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>eac_ctx</name>
    <filename>structeac__ctx.html</filename>
    <member kind="function">
      <type></type>
      <name>STACK_OF</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>aba9bee0f71ee1e7483f6e4ad6a14e173</anchor>
      <arglist>(PACE_CTX *) pace_ctxs</arglist>
    </member>
    <member kind="function">
      <type></type>
      <name>STACK_OF</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>a9ef2db2812d568bb5d9518b9143c0613</anchor>
      <arglist>(RI_CTX *) ri_ctxs</arglist>
    </member>
    <member kind="function">
      <type></type>
      <name>STACK_OF</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>a23783fc5062b4767f151e13c3eec7e6b</anchor>
      <arglist>(CA_CTX *) ca_ctxs</arglist>
    </member>
    <member kind="variable">
      <type>enum eac_tr_version</type>
      <name>tr_version</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>af35b8ee2566fcb58b784d18c6955b044</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BN_CTX *</type>
      <name>bn_ctx</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>aa4689aae53a76259fc0a5b6986beed44</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>EVP_MD_CTX *</type>
      <name>md_ctx</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>a66f01e318e94ef27f184496c1ee08258</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>EVP_CIPHER_CTX *</type>
      <name>cipher_ctx</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>ae4ae226d67fed219a32807c74246f96d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>PACE_CTX *</type>
      <name>pace_ctx</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>a932f295824a7c470be10a2399692b14e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>RI_CTX *</type>
      <name>ri_ctx</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>aeba652c7c12edbc1154c329f923e516d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>TA_CTX *</type>
      <name>ta_ctx</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>a2d80bb6842313788c23c422d12c81437</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>CA_CTX *</type>
      <name>ca_ctx</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>a335d8db00b3c531ec2a8bdf70259a487</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>KA_CTX *</type>
      <name>key_ctx</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>a920e45bffa7ac62240aa98b448286aac</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BIGNUM *</type>
      <name>ssc</name>
      <anchorfile>structeac__ctx.html</anchorfile>
      <anchor>ac5ac966e53d3d76ea6861a7bf8e5ad5b</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>ka_ctx</name>
    <filename>structka__ctx.html</filename>
    <member kind="variable">
      <type>const EVP_MD *</type>
      <name>md</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>a745aa4812acdf1ea3f08549c09ba1a09</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ENGINE *</type>
      <name>md_engine</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>a3706295ac5dda046703d902f883766eb</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>CMAC_CTX *</type>
      <name>cmac_ctx</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>aa2ba5bdac4b20c2b4add9cdcb505cf04</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const EVP_CIPHER *</type>
      <name>cipher</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>a6249dbb3a4ae07996486bc9b8b36d502</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ENGINE *</type>
      <name>cipher_engine</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>a2802cdc905121995ed131f2964acd2f8</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>unsigned char *</type>
      <name>iv</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>af735a85606610d4d19cf151af4f84acf</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>mac_keylen</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>adb07ad439522dd039b82ab98df682a82</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>enc_keylen</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>a44649e3f01e85ba3493a39a8eb2c7412</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *(*</type>
      <name>generate_key</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>a014527b2e7c2d29b9ea3d696b0f6f27d</anchor>
      <arglist>)(EVP_PKEY *key, BN_CTX *bn_ctx)</arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *(*</type>
      <name>compute_key</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>a49b570f5c82aeab28d087c8294780031</anchor>
      <arglist>)(EVP_PKEY *key, const BUF_MEM *in, BN_CTX *bn_ctx)</arglist>
    </member>
    <member kind="variable">
      <type>EVP_PKEY *</type>
      <name>key</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>a67c28ed126bc0cc85b21f854edb1c6bc</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *</type>
      <name>shared_secret</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>aa1bbed50cc0903ae872e4b19ac2c7226</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *</type>
      <name>k_enc</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>a4b9ab1a97367a0a25f4c8fc27520abc7</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *</type>
      <name>k_mac</name>
      <anchorfile>structka__ctx.html</anchorfile>
      <anchor>a2fa30aa5aa06ddc90382cdaf904c34a1</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>pace_ctx</name>
    <filename>structpace__ctx.html</filename>
    <member kind="variable">
      <type>int</type>
      <name>protocol</name>
      <anchorfile>structpace__ctx.html</anchorfile>
      <anchor>af97dcc517de0fde8e83a7aa40f50da3e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>unsigned char</type>
      <name>version</name>
      <anchorfile>structpace__ctx.html</anchorfile>
      <anchor>a1e1c98e8c010ac57c1529d4a7ac7d140</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>id</name>
      <anchorfile>structpace__ctx.html</anchorfile>
      <anchor>af298b849509aa042d7704348e89d09d7</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *(*</type>
      <name>map_generate_key</name>
      <anchorfile>structpace__ctx.html</anchorfile>
      <anchor>a693587f2f0ce3376e02308dd55152bc9</anchor>
      <arglist>)(const struct pace_ctx *ctx, BN_CTX *bn_ctx)</arglist>
    </member>
    <member kind="variable">
      <type>int(*</type>
      <name>map_compute_key</name>
      <anchorfile>structpace__ctx.html</anchorfile>
      <anchor>a989c4b5e086fdd04a2efb08a24c70d55</anchor>
      <arglist>)(struct pace_ctx *ctx, const BUF_MEM *s, const BUF_MEM *in, BN_CTX *bn_ctx)</arglist>
    </member>
    <member kind="variable">
      <type>EVP_PKEY *</type>
      <name>static_key</name>
      <anchorfile>structpace__ctx.html</anchorfile>
      <anchor>a9e8dc5891a4991d3ee15681959a530f4</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>KA_CTX *</type>
      <name>ka_ctx</name>
      <anchorfile>structpace__ctx.html</anchorfile>
      <anchor>a13ac5102711cf4fe79065811bff0fb2c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *</type>
      <name>nonce</name>
      <anchorfile>structpace__ctx.html</anchorfile>
      <anchor>a01213725b7c8d6e154b9b0d78d4dd2d8</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *</type>
      <name>my_eph_pubkey</name>
      <anchorfile>structpace__ctx.html</anchorfile>
      <anchor>a3d6695ce3c69a1b98d33fac739cdc31b</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>pace_sec</name>
    <filename>structpace__sec.html</filename>
    <member kind="variable">
      <type>enum s_type</type>
      <name>type</name>
      <anchorfile>structpace__sec.html</anchorfile>
      <anchor>a4edee42cfb3cbaa2ca7a0612e5bfd70a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *</type>
      <name>mem</name>
      <anchorfile>structpace__sec.html</anchorfile>
      <anchor>a0f6398c39c804664105a8b9595618894</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *</type>
      <name>encoded</name>
      <anchorfile>structpace__sec.html</anchorfile>
      <anchor>ab10cebaa4080f060c6e2be702129a2bf</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>ri_ctx</name>
    <filename>structri__ctx.html</filename>
    <member kind="variable">
      <type>int</type>
      <name>protocol</name>
      <anchorfile>structri__ctx.html</anchorfile>
      <anchor>a26dcc3b24d0be9e786f73da29ac14078</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>id</name>
      <anchorfile>structri__ctx.html</anchorfile>
      <anchor>aa02f62fa11872a3ea637b934dca3de9e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const EVP_MD *</type>
      <name>md</name>
      <anchorfile>structri__ctx.html</anchorfile>
      <anchor>ad6a276a184c01a115b8f6f602aea0bf5</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *(*</type>
      <name>generate_key</name>
      <anchorfile>structri__ctx.html</anchorfile>
      <anchor>a0575020ded3354b7de0bcbfb893ec865</anchor>
      <arglist>)(EVP_PKEY *key, BN_CTX *bn_ctx)</arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *(*</type>
      <name>compute_key</name>
      <anchorfile>structri__ctx.html</anchorfile>
      <anchor>a83529722bfbf8b9071d44380b51abe61</anchor>
      <arglist>)(EVP_PKEY *key, const BUF_MEM *in, BN_CTX *bn_ctx)</arglist>
    </member>
    <member kind="variable">
      <type>EVP_PKEY *</type>
      <name>static_key</name>
      <anchorfile>structri__ctx.html</anchorfile>
      <anchor>a8de84de9b8a818bfc0f6910d2b6d1505</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>ta_ctx</name>
    <filename>structta__ctx.html</filename>
    <member kind="variable">
      <type>unsigned char</type>
      <name>version</name>
      <anchorfile>structta__ctx.html</anchorfile>
      <anchor>a6e976bf9c7771c2f06405aa17cd45741</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>protocol</name>
      <anchorfile>structta__ctx.html</anchorfile>
      <anchor>aab0b4778bb8406c6dfcae630a7ee953d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>ENGINE *</type>
      <name>key_engine</name>
      <anchorfile>structta__ctx.html</anchorfile>
      <anchor>a1691c4c8e297c12194f292ec4b9562ef</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>EVP_PKEY *</type>
      <name>priv_key</name>
      <anchorfile>structta__ctx.html</anchorfile>
      <anchor>a345e76e2dbe501008d567a0394bdc477</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>EVP_PKEY *</type>
      <name>pub_key</name>
      <anchorfile>structta__ctx.html</anchorfile>
      <anchor>a003a31cec341cc32c7c8d3020674bdf4</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *</type>
      <name>pk_pcd</name>
      <anchorfile>structta__ctx.html</anchorfile>
      <anchor>a5024a276b503f26170e0f119ff770e18</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>BUF_MEM *</type>
      <name>nonce</name>
      <anchorfile>structta__ctx.html</anchorfile>
      <anchor>a15f1a7fc87648ca8bb8a918d2b8c1d7a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>CVC_CERT *</type>
      <name>trust_anchor</name>
      <anchorfile>structta__ctx.html</anchorfile>
      <anchor>a5fa8c24d79d367f6573687d2fb98e298</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>CVC_CERT *</type>
      <name>current_cert</name>
      <anchorfile>structta__ctx.html</anchorfile>
      <anchor>a69786f37170911c75aeb2cad26f287c6</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>CVC_CERT *</type>
      <name>new_trust_anchor</name>
      <anchorfile>structta__ctx.html</anchorfile>
      <anchor>a0158428cd0d0deaf19a7efe00fa75ad7</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>flags</name>
      <anchorfile>structta__ctx.html</anchorfile>
      <anchor>a78ef4b31a6f23f6760214a1fcdaff815</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>CVC_lookup_cvca_cert</type>
      <name>lookup_cvca_cert</name>
      <anchorfile>structta__ctx.html</anchorfile>
      <anchor>a42c4f67266f5489bce3a59d937380c33</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="dir">
    <name>eac</name>
    <path>/home/fm/Dokumente/openpace/src/eac/</path>
    <filename>dir_2beb2c8fad66f6564e9cdda73fb11327.html</filename>
    <file>ca.h</file>
    <file>cv_cert.h</file>
    <file>eac.h</file>
    <file>objects.h</file>
    <file>pace.h</file>
    <file>ri.h</file>
    <file>ta.h</file>
  </compound>
</tagfile>
