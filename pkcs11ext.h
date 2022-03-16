#define NSSCK_VENDOR_NETSCAPE  		0x4E534350 /* NSCP */
#define NSSCK_VENDOR_PKSC11_RU_TEAM 	0xc4321000
#define NSSCK_VENDOR_ALADDIN 		0xc4900000

#define CKD_GOST_KDF   		(NSSCK_VENDOR_PKSC11_RU_TEAM|0x001)
#define CKD_TK26_CPDIVERSIFY_KDF CKD_GOST_KDF

#define CKA_TK26_GOSTR3410_PARAMS    (NSSCK_VENDOR_PKSC11_RU_TEAM|0x001)
#define CKA_TK26_GOSTR3411_PARAMS    (NSSCK_VENDOR_PKSC11_RU_TEAM|0x002)
#define CKA_TK26_GOST28147_PARAMS    (NSSCK_VENDOR_PKSC11_RU_TEAM|0x003)

#define CKM_TK26_GOSTR341094_KEY_PAIR_GEN   (NSSCK_VENDOR_PKSC11_RU_TEAM|0x000)
#define CKM_TK26_GOSTR341094                (NSSCK_VENDOR_PKSC11_RU_TEAM|0x001)
#define CKM_TK26_GOSTR341094_WITH_GOSTR3411 (NSSCK_VENDOR_PKSC11_RU_TEAM|0x002)
#define CKM_TK26_GOSTR341094_KEY_WRAP       (NSSCK_VENDOR_PKSC11_RU_TEAM|0x004)

#define CKK_TK26_GOSTR341094   (NSSCK_VENDOR_PKSC11_RU_TEAM|0x000)
#define CKK_TK26_GOSTR3410     (NSSCK_VENDOR_PKSC11_RU_TEAM|0x001)
#define CKK_TK26_GOSTR3411     (NSSCK_VENDOR_PKSC11_RU_TEAM|0x002)
#define CKK_TK26_GOST28147     (NSSCK_VENDOR_PKSC11_RU_TEAM|0x003)

#define CKM_TK26_GOSTR3410_KEY_PAIR_GEN (NSSCK_VENDOR_PKSC11_RU_TEAM|0x010)
#define CKM_TK26_GOSTR3410              (NSSCK_VENDOR_PKSC11_RU_TEAM|0x011)
#define CKM_TK26_GOSTR3410_WITH_GOSTR3411    (NSSCK_VENDOR_PKSC11_RU_TEAM|0x012)
#define CKM_TK26_GOSTR3410_DERIVE       (NSSCK_VENDOR_PKSC11_RU_TEAM|0x013)
#define CKM_TK26_GOSTR3410_KEY_WRAP     (NSSCK_VENDOR_PKSC11_RU_TEAM|0x014)

#define CKM_TK26_GOSTR3411                (NSSCK_VENDOR_PKSC11_RU_TEAM|0x020)
#define CKM_TK26_GOSTR3411_HMAC           (NSSCK_VENDOR_PKSC11_RU_TEAM|0x021)
#define CKM_TK26_GOST28147_KEY_GEN        (NSSCK_VENDOR_PKSC11_RU_TEAM|0x030)
#define CKM_TK26_GOST28147_ECB            (NSSCK_VENDOR_PKSC11_RU_TEAM|0x031)
#define CKM_TK26_GOST28147                (NSSCK_VENDOR_PKSC11_RU_TEAM|0x032)
#define CKM_TK26_GOST28147_MAC            (NSSCK_VENDOR_PKSC11_RU_TEAM|0x033)
#define CKM_TK26_GOST28147_KEY_WRAP       (NSSCK_VENDOR_PKSC11_RU_TEAM|0x036)


/* old, erroneous, deprecated,
 application backward compatibility only 64-byte (512-bit) buffer */
#define CKM_PBA_GOSTR3411_WITH_GOSTR3411_HMAC_CRYPTOPRO \
                                               (NSSCK_VENDOR_PKSC11_RU_TEAM|0x034)
/* correct, 32-byte (256-bit) buffer */
#define CKM_PBA_GOSTR3411_WITH_GOSTR3411_HMAC \
                                               (NSSCK_VENDOR_PKSC11_RU_TEAM|0x035)
#define CKM_TLS_GOST_MASTER_KEY_DERIVE         (NSSCK_VENDOR_PKSC11_RU_TEAM|0x101)
#define CKM_TLS_GOST_KEY_AND_MAC_DERIVE        (NSSCK_VENDOR_PKSC11_RU_TEAM|0x102)
#define CKM_TLS_GOST_PRF                       (NSSCK_VENDOR_PKSC11_RU_TEAM|0x103)
#define CKM_TLS_GOST_PRE_MASTER_KEY_GEN        (NSSCK_VENDOR_PKSC11_RU_TEAM|0x104)

/* special derive mech for UEK */
#define CKM_UEK_DERIVE        (NSSCK_VENDOR_ALADDIN|0x001)

/*
 * Netscape-defined crypto mechanisms
 *
 */
#define CKM_NETSCAPE (CKM_VENDOR_DEFINED|NSSCK_VENDOR_NETSCAPE)
/*
 * HISTORICAL:
 * Do not attempt to use these. They are only used by NETSCAPE's internal
 * PKCS #11 interface. Most of these are place holders for other mechanism
 * and will change in the future.
 */
#define CKM_NETSCAPE_PBE_SHA1_DES_CBC           0x80000002L
#define CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC    0x80000003L
#define CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC    0x80000004L
#define CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC   0x80000005L
#define CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4        0x80000006L
#define CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4       0x80000007L
#define CKM_NETSCAPE_PBE_SHA1_FAULTY_3DES_CBC   0x80000008L
#define CKM_NETSCAPE_PBE_SHA1_HMAC_KEY_GEN      0x80000009L
#define CKM_NETSCAPE_PBE_MD5_HMAC_KEY_GEN       0x8000000aL
#define CKM_NETSCAPE_PBE_MD2_HMAC_KEY_GEN       0x8000000bL

#define CKM_TLS_PRF_GENERAL                     0x80000373L
