// Copyright 2013 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs11

import "fmt"

const (
	CK_TRUE                              = 1
	CK_FALSE                             = 0
	CK_UNAVAILABLE_INFORMATION           = ^uint(0)
	CK_EFFECTIVELY_INFINITE              = 0
	CK_INVALID_HANDLE                    = 0
	CKN_SURRENDER                        = 0
	CKN_OTP_CHANGED                      = 1
	CKF_TOKEN_PRESENT                    = 0x00000001
	CKF_REMOVABLE_DEVICE                 = 0x00000002
	CKF_HW_SLOT                          = 0x00000004
	CKF_RNG                              = 0x00000001
	CKF_WRITE_PROTECTED                  = 0x00000002
	CKF_LOGIN_REQUIRED                   = 0x00000004
	CKF_USER_PIN_INITIALIZED             = 0x00000008
	CKF_RESTORE_KEY_NOT_NEEDED           = 0x00000020
	CKF_CLOCK_ON_TOKEN                   = 0x00000040
	CKF_PROTECTED_AUTHENTICATION_PATH    = 0x00000100
	CKF_DUAL_CRYPTO_OPERATIONS           = 0x00000200
	CKF_TOKEN_INITIALIZED                = 0x00000400
	CKF_SECONDARY_AUTHENTICATION         = 0x00000800
	CKF_USER_PIN_COUNT_LOW               = 0x00010000
	CKF_USER_PIN_FINAL_TRY               = 0x00020000
	CKF_USER_PIN_LOCKED                  = 0x00040000
	CKF_USER_PIN_TO_BE_CHANGED           = 0x00080000
	CKF_SO_PIN_COUNT_LOW                 = 0x00100000
	CKF_SO_PIN_FINAL_TRY                 = 0x00200000
	CKF_SO_PIN_LOCKED                    = 0x00400000
	CKF_SO_PIN_TO_BE_CHANGED             = 0x00800000
	CKF_ERROR_STATE                      = 0x01000000
	CKU_SO                               = 0
	CKU_USER                             = 1
	CKU_CONTEXT_SPECIFIC                 = 2
	CKS_RO_PUBLIC_SESSION                = 0
	CKS_RO_USER_FUNCTIONS                = 1
	CKS_RW_PUBLIC_SESSION                = 2
	CKS_RW_USER_FUNCTIONS                = 3
	CKS_RW_SO_FUNCTIONS                  = 4
	CKF_RW_SESSION                       = 0x00000002
	CKF_SERIAL_SESSION                   = 0x00000004
	CKO_DATA                             = 0x00000000
	CKO_CERTIFICATE                      = 0x00000001
	CKO_PUBLIC_KEY                       = 0x00000002
	CKO_PRIVATE_KEY                      = 0x00000003
	CKO_SECRET_KEY                       = 0x00000004
	CKO_HW_FEATURE                       = 0x00000005
	CKO_DOMAIN_PARAMETERS                = 0x00000006
	CKO_MECHANISM                        = 0x00000007
	CKO_OTP_KEY                          = 0x00000008
	CKO_VENDOR_DEFINED                   = 0x80000000
	CKH_MONOTONIC_COUNTER                = 0x00000001
	CKH_CLOCK                            = 0x00000002
	CKH_USER_INTERFACE                   = 0x00000003
	CKH_VENDOR_DEFINED                   = 0x80000000
	CKK_RSA                              = 0x00000000
	CKK_DSA                              = 0x00000001
	CKK_DH                               = 0x00000002
	CKK_ECDSA                            = 0x00000003 // Deprecated
	CKK_EC                               = 0x00000003
	CKK_X9_42_DH                         = 0x00000004
	CKK_KEA                              = 0x00000005
	CKK_GENERIC_SECRET                   = 0x00000010
	CKK_RC2                              = 0x00000011
	CKK_RC4                              = 0x00000012
	CKK_DES                              = 0x00000013
	CKK_DES2                             = 0x00000014
	CKK_DES3                             = 0x00000015
	CKK_CAST                             = 0x00000016
	CKK_CAST3                            = 0x00000017
	CKK_CAST5                            = 0x00000018 // Deprecated
	CKK_CAST128                          = 0x00000018
	CKK_RC5                              = 0x00000019
	CKK_IDEA                             = 0x0000001A
	CKK_SKIPJACK                         = 0x0000001B
	CKK_BATON                            = 0x0000001C
	CKK_JUNIPER                          = 0x0000001D
	CKK_CDMF                             = 0x0000001E
	CKK_AES                              = 0x0000001F
	CKK_BLOWFISH                         = 0x00000020
	CKK_TWOFISH                          = 0x00000021
	CKK_SECURID                          = 0x00000022
	CKK_HOTP                             = 0x00000023
	CKK_ACTI                             = 0x00000024
	CKK_CAMELLIA                         = 0x00000025
	CKK_ARIA                             = 0x00000026
	CKK_MD5_HMAC                         = 0x00000027
	CKK_SHA_1_HMAC                       = 0x00000028
	CKK_RIPEMD128_HMAC                   = 0x00000029
	CKK_RIPEMD160_HMAC                   = 0x0000002A
	CKK_SHA256_HMAC                      = 0x0000002B
	CKK_SHA384_HMAC                      = 0x0000002C
	CKK_SHA512_HMAC                      = 0x0000002D
	CKK_SHA224_HMAC                      = 0x0000002E
	CKK_SEED                             = 0x0000002F
	CKK_GOSTR3410                        = 0x00000030
	CKK_GOSTR3411                        = 0x00000031
	CKK_GOST28147                        = 0x00000032
	CKK_SHA3_224_HMAC                    = 0x00000033
	CKK_SHA3_256_HMAC                    = 0x00000034
	CKK_SHA3_384_HMAC                    = 0x00000035
	CKK_SHA3_512_HMAC                    = 0x00000036
	CKK_VENDOR_DEFINED                   = 0x80000000
	CK_CERTIFICATE_CATEGORY_UNSPECIFIED  = 0
	CK_CERTIFICATE_CATEGORY_TOKEN_USER   = 1
	CK_CERTIFICATE_CATEGORY_AUTHORITY    = 2
	CK_CERTIFICATE_CATEGORY_OTHER_ENTITY = 3
	CK_SECURITY_DOMAIN_UNSPECIFIED       = 0
	CK_SECURITY_DOMAIN_MANUFACTURER      = 1
	CK_SECURITY_DOMAIN_OPERATOR          = 2
	CK_SECURITY_DOMAIN_THIRD_PARTY       = 3
	CKC_X_509                            = 0x00000000
	CKC_X_509_ATTR_CERT                  = 0x00000001
	CKC_WTLS                             = 0x00000002
	CKC_VENDOR_DEFINED                   = 0x80000000
	CKF_ARRAY_ATTRIBUTE                  = 0x40000000
	CK_OTP_FORMAT_DECIMAL                = 0
	CK_OTP_FORMAT_HEXADECIMAL            = 1
	CK_OTP_FORMAT_ALPHANUMERIC           = 2
	CK_OTP_FORMAT_BINARY                 = 3
	CK_OTP_PARAM_IGNORED                 = 0
	CK_OTP_PARAM_OPTIONAL                = 1
	CK_OTP_PARAM_MANDATORY               = 2
	CKA_CLASS                            = 0x00000000
	CKA_TOKEN                            = 0x00000001
	CKA_PRIVATE                          = 0x00000002
	CKA_LABEL                            = 0x00000003
	CKA_APPLICATION                      = 0x00000010
	CKA_VALUE                            = 0x00000011
	CKA_OBJECT_ID                        = 0x00000012
	CKA_CERTIFICATE_TYPE                 = 0x00000080
	CKA_ISSUER                           = 0x00000081
	CKA_SERIAL_NUMBER                    = 0x00000082
	CKA_AC_ISSUER                        = 0x00000083
	CKA_OWNER                            = 0x00000084
	CKA_ATTR_TYPES                       = 0x00000085
	CKA_TRUSTED                          = 0x00000086
	CKA_CERTIFICATE_CATEGORY             = 0x00000087
	CKA_JAVA_MIDP_SECURITY_DOMAIN        = 0x00000088
	CKA_URL                              = 0x00000089
	CKA_HASH_OF_SUBJECT_PUBLIC_KEY       = 0x0000008A
	CKA_HASH_OF_ISSUER_PUBLIC_KEY        = 0x0000008B
	CKA_NAME_HASH_ALGORITHM              = 0x0000008C
	CKA_CHECK_VALUE                      = 0x00000090
	CKA_KEY_TYPE                         = 0x00000100
	CKA_SUBJECT                          = 0x00000101
	CKA_ID                               = 0x00000102
	CKA_SENSITIVE                        = 0x00000103
	CKA_ENCRYPT                          = 0x00000104
	CKA_DECRYPT                          = 0x00000105
	CKA_WRAP                             = 0x00000106
	CKA_UNWRAP                           = 0x00000107
	CKA_SIGN                             = 0x00000108
	CKA_SIGN_RECOVER                     = 0x00000109
	CKA_VERIFY                           = 0x0000010A
	CKA_VERIFY_RECOVER                   = 0x0000010B
	CKA_DERIVE                           = 0x0000010C
	CKA_START_DATE                       = 0x00000110
	CKA_END_DATE                         = 0x00000111
	CKA_MODULUS                          = 0x00000120
	CKA_MODULUS_BITS                     = 0x00000121
	CKA_PUBLIC_EXPONENT                  = 0x00000122
	CKA_PRIVATE_EXPONENT                 = 0x00000123
	CKA_PRIME_1                          = 0x00000124
	CKA_PRIME_2                          = 0x00000125
	CKA_EXPONENT_1                       = 0x00000126
	CKA_EXPONENT_2                       = 0x00000127
	CKA_COEFFICIENT                      = 0x00000128
	CKA_PUBLIC_KEY_INFO                  = 0x00000129
	CKA_PRIME                            = 0x00000130
	CKA_SUBPRIME                         = 0x00000131
	CKA_BASE                             = 0x00000132
	CKA_PRIME_BITS                       = 0x00000133
	CKA_SUBPRIME_BITS                    = 0x00000134
	CKA_SUB_PRIME_BITS                   = CKA_SUBPRIME_BITS
	CKA_VALUE_BITS                       = 0x00000160
	CKA_VALUE_LEN                        = 0x00000161
	CKA_EXTRACTABLE                      = 0x00000162
	CKA_LOCAL                            = 0x00000163
	CKA_NEVER_EXTRACTABLE                = 0x00000164
	CKA_ALWAYS_SENSITIVE                 = 0x00000165
	CKA_KEY_GEN_MECHANISM                = 0x00000166
	CKA_MODIFIABLE                       = 0x00000170
	CKA_COPYABLE                         = 0x00000171
	CKA_DESTROYABLE                      = 0x00000172
	CKA_ECDSA_PARAMS                     = 0x00000180 // Deprecated
	CKA_EC_PARAMS                        = 0x00000180
	CKA_EC_POINT                         = 0x00000181
	CKA_SECONDARY_AUTH                   = 0x00000200 // Deprecated
	CKA_AUTH_PIN_FLAGS                   = 0x00000201 // Deprecated
	CKA_ALWAYS_AUTHENTICATE              = 0x00000202
	CKA_WRAP_WITH_TRUSTED                = 0x00000210
	CKA_WRAP_TEMPLATE                    = (CKF_ARRAY_ATTRIBUTE | 0x00000211)
	CKA_UNWRAP_TEMPLATE                  = (CKF_ARRAY_ATTRIBUTE | 0x00000212)
	CKA_DERIVE_TEMPLATE                  = (CKF_ARRAY_ATTRIBUTE | 0x00000213)
	CKA_OTP_FORMAT                       = 0x00000220
	CKA_OTP_LENGTH                       = 0x00000221
	CKA_OTP_TIME_INTERVAL                = 0x00000222
	CKA_OTP_USER_FRIENDLY_MODE           = 0x00000223
	CKA_OTP_CHALLENGE_REQUIREMENT        = 0x00000224
	CKA_OTP_TIME_REQUIREMENT             = 0x00000225
	CKA_OTP_COUNTER_REQUIREMENT          = 0x00000226
	CKA_OTP_PIN_REQUIREMENT              = 0x00000227
	CKA_OTP_COUNTER                      = 0x0000022E
	CKA_OTP_TIME                         = 0x0000022F
	CKA_OTP_USER_IDENTIFIER              = 0x0000022A
	CKA_OTP_SERVICE_IDENTIFIER           = 0x0000022B
	CKA_OTP_SERVICE_LOGO                 = 0x0000022C
	CKA_OTP_SERVICE_LOGO_TYPE            = 0x0000022D
	CKA_GOSTR3410_PARAMS                 = 0x00000250
	CKA_GOSTR3411_PARAMS                 = 0x00000251
	CKA_GOST28147_PARAMS                 = 0x00000252
	CKA_HW_FEATURE_TYPE                  = 0x00000300
	CKA_RESET_ON_INIT                    = 0x00000301
	CKA_HAS_RESET                        = 0x00000302
	CKA_PIXEL_X                          = 0x00000400
	CKA_PIXEL_Y                          = 0x00000401
	CKA_RESOLUTION                       = 0x00000402
	CKA_CHAR_ROWS                        = 0x00000403
	CKA_CHAR_COLUMNS                     = 0x00000404
	CKA_COLOR                            = 0x00000405
	CKA_BITS_PER_PIXEL                   = 0x00000406
	CKA_CHAR_SETS                        = 0x00000480
	CKA_ENCODING_METHODS                 = 0x00000481
	CKA_MIME_TYPES                       = 0x00000482
	CKA_MECHANISM_TYPE                   = 0x00000500
	CKA_REQUIRED_CMS_ATTRIBUTES          = 0x00000501
	CKA_DEFAULT_CMS_ATTRIBUTES           = 0x00000502
	CKA_SUPPORTED_CMS_ATTRIBUTES         = 0x00000503
	CKA_ALLOWED_MECHANISMS               = (CKF_ARRAY_ATTRIBUTE | 0x00000600)
	CKA_VENDOR_DEFINED                   = 0x80000000
	CKM_RSA_PKCS_KEY_PAIR_GEN            = 0x00000000
	CKM_RSA_PKCS                         = 0x00000001
	CKM_RSA_9796                         = 0x00000002
	CKM_RSA_X_509                        = 0x00000003
	CKM_MD2_RSA_PKCS                     = 0x00000004
	CKM_MD5_RSA_PKCS                     = 0x00000005
	CKM_SHA1_RSA_PKCS                    = 0x00000006
	CKM_RIPEMD128_RSA_PKCS               = 0x00000007
	CKM_RIPEMD160_RSA_PKCS               = 0x00000008
	CKM_RSA_PKCS_OAEP                    = 0x00000009
	CKM_RSA_X9_31_KEY_PAIR_GEN           = 0x0000000A
	CKM_RSA_X9_31                        = 0x0000000B
	CKM_SHA1_RSA_X9_31                   = 0x0000000C
	CKM_RSA_PKCS_PSS                     = 0x0000000D
	CKM_SHA1_RSA_PKCS_PSS                = 0x0000000E
	CKM_DSA_KEY_PAIR_GEN                 = 0x00000010
	CKM_DSA                              = 0x00000011
	CKM_DSA_SHA1                         = 0x00000012
	CKM_DSA_SHA224                       = 0x00000013
	CKM_DSA_SHA256                       = 0x00000014
	CKM_DSA_SHA384                       = 0x00000015
	CKM_DSA_SHA512                       = 0x00000016
	CKM_DSA_SHA3_224                     = 0x00000018
	CKM_DSA_SHA3_256                     = 0x00000019
	CKM_DSA_SHA3_384                     = 0x0000001A
	CKM_DSA_SHA3_512                     = 0x0000001B
	CKM_DH_PKCS_KEY_PAIR_GEN             = 0x00000020
	CKM_DH_PKCS_DERIVE                   = 0x00000021
	CKM_X9_42_DH_KEY_PAIR_GEN            = 0x00000030
	CKM_X9_42_DH_DERIVE                  = 0x00000031
	CKM_X9_42_DH_HYBRID_DERIVE           = 0x00000032
	CKM_X9_42_MQV_DERIVE                 = 0x00000033
	CKM_SHA256_RSA_PKCS                  = 0x00000040
	CKM_SHA384_RSA_PKCS                  = 0x00000041
	CKM_SHA512_RSA_PKCS                  = 0x00000042
	CKM_SHA256_RSA_PKCS_PSS              = 0x00000043
	CKM_SHA384_RSA_PKCS_PSS              = 0x00000044
	CKM_SHA512_RSA_PKCS_PSS              = 0x00000045
	CKM_SHA224_RSA_PKCS                  = 0x00000046
	CKM_SHA224_RSA_PKCS_PSS              = 0x00000047
	CKM_SHA512_224                       = 0x00000048
	CKM_SHA512_224_HMAC                  = 0x00000049
	CKM_SHA512_224_HMAC_GENERAL          = 0x0000004A
	CKM_SHA512_224_KEY_DERIVATION        = 0x0000004B
	CKM_SHA512_256                       = 0x0000004C
	CKM_SHA512_256_HMAC                  = 0x0000004D
	CKM_SHA512_256_HMAC_GENERAL          = 0x0000004E
	CKM_SHA512_256_KEY_DERIVATION        = 0x0000004F
	CKM_SHA512_T                         = 0x00000050
	CKM_SHA512_T_HMAC                    = 0x00000051
	CKM_SHA512_T_HMAC_GENERAL            = 0x00000052
	CKM_SHA512_T_KEY_DERIVATION          = 0x00000053
	CKM_SHA3_256_RSA_PKCS                = 0x00000060
	CKM_SHA3_384_RSA_PKCS                = 0x00000061
	CKM_SHA3_512_RSA_PKCS                = 0x00000062
	CKM_SHA3_256_RSA_PKCS_PSS            = 0x00000063
	CKM_SHA3_384_RSA_PKCS_PSS            = 0x00000064
	CKM_SHA3_512_RSA_PKCS_PSS            = 0x00000065
	CKM_SHA3_224_RSA_PKCS                = 0x00000066
	CKM_SHA3_224_RSA_PKCS_PSS            = 0x00000067
	CKM_RC2_KEY_GEN                      = 0x00000100
	CKM_RC2_ECB                          = 0x00000101
	CKM_RC2_CBC                          = 0x00000102
	CKM_RC2_MAC                          = 0x00000103
	CKM_RC2_MAC_GENERAL                  = 0x00000104
	CKM_RC2_CBC_PAD                      = 0x00000105
	CKM_RC4_KEY_GEN                      = 0x00000110
	CKM_RC4                              = 0x00000111
	CKM_DES_KEY_GEN                      = 0x00000120
	CKM_DES_ECB                          = 0x00000121
	CKM_DES_CBC                          = 0x00000122
	CKM_DES_MAC                          = 0x00000123
	CKM_DES_MAC_GENERAL                  = 0x00000124
	CKM_DES_CBC_PAD                      = 0x00000125
	CKM_DES2_KEY_GEN                     = 0x00000130
	CKM_DES3_KEY_GEN                     = 0x00000131
	CKM_DES3_ECB                         = 0x00000132
	CKM_DES3_CBC                         = 0x00000133
	CKM_DES3_MAC                         = 0x00000134
	CKM_DES3_MAC_GENERAL                 = 0x00000135
	CKM_DES3_CBC_PAD                     = 0x00000136
	CKM_DES3_CMAC_GENERAL                = 0x00000137
	CKM_DES3_CMAC                        = 0x00000138
	CKM_CDMF_KEY_GEN                     = 0x00000140
	CKM_CDMF_ECB                         = 0x00000141
	CKM_CDMF_CBC                         = 0x00000142
	CKM_CDMF_MAC                         = 0x00000143
	CKM_CDMF_MAC_GENERAL                 = 0x00000144
	CKM_CDMF_CBC_PAD                     = 0x00000145
	CKM_DES_OFB64                        = 0x00000150
	CKM_DES_OFB8                         = 0x00000151
	CKM_DES_CFB64                        = 0x00000152
	CKM_DES_CFB8                         = 0x00000153
	CKM_MD2                              = 0x00000200
	CKM_MD2_HMAC                         = 0x00000201
	CKM_MD2_HMAC_GENERAL                 = 0x00000202
	CKM_MD5                              = 0x00000210
	CKM_MD5_HMAC                         = 0x00000211
	CKM_MD5_HMAC_GENERAL                 = 0x00000212
	CKM_SHA_1                            = 0x00000220
	CKM_SHA_1_HMAC                       = 0x00000221
	CKM_SHA_1_HMAC_GENERAL               = 0x00000222
	CKM_RIPEMD128                        = 0x00000230
	CKM_RIPEMD128_HMAC                   = 0x00000231
	CKM_RIPEMD128_HMAC_GENERAL           = 0x00000232
	CKM_RIPEMD160                        = 0x00000240
	CKM_RIPEMD160_HMAC                   = 0x00000241
	CKM_RIPEMD160_HMAC_GENERAL           = 0x00000242
	CKM_SHA256                           = 0x00000250
	CKM_SHA256_HMAC                      = 0x00000251
	CKM_SHA256_HMAC_GENERAL              = 0x00000252
	CKM_SHA224                           = 0x00000255
	CKM_SHA224_HMAC                      = 0x00000256
	CKM_SHA224_HMAC_GENERAL              = 0x00000257
	CKM_SHA384                           = 0x00000260
	CKM_SHA384_HMAC                      = 0x00000261
	CKM_SHA384_HMAC_GENERAL              = 0x00000262
	CKM_SHA512                           = 0x00000270
	CKM_SHA512_HMAC                      = 0x00000271
	CKM_SHA512_HMAC_GENERAL              = 0x00000272
	CKM_SECURID_KEY_GEN                  = 0x00000280
	CKM_SECURID                          = 0x00000282
	CKM_HOTP_KEY_GEN                     = 0x00000290
	CKM_HOTP                             = 0x00000291
	CKM_ACTI                             = 0x000002A0
	CKM_ACTI_KEY_GEN                     = 0x000002A1
	CKM_SHA3_256                         = 0x000002B0
	CKM_SHA3_256_HMAC                    = 0x000002B1
	CKM_SHA3_256_HMAC_GENERAL            = 0x000002B2
	CKM_SHA3_256_KEY_GEN                 = 0x000002B3
	CKM_SHA3_224                         = 0x000002B5
	CKM_SHA3_224_HMAC                    = 0x000002B6
	CKM_SHA3_224_HMAC_GENERAL            = 0x000002B7
	CKM_SHA3_224_KEY_GEN                 = 0x000002B8
	CKM_SHA3_384                         = 0x000002C0
	CKM_SHA3_384_HMAC                    = 0x000002C1
	CKM_SHA3_384_HMAC_GENERAL            = 0x000002C2
	CKM_SHA3_384_KEY_GEN                 = 0x000002C3
	CKM_SHA3_512                         = 0x000002D0
	CKM_SHA3_512_HMAC                    = 0x000002D1
	CKM_SHA3_512_HMAC_GENERAL            = 0x000002D2
	CKM_SHA3_512_KEY_GEN                 = 0x000002D3
	CKM_CAST_KEY_GEN                     = 0x00000300
	CKM_CAST_ECB                         = 0x00000301
	CKM_CAST_CBC                         = 0x00000302
	CKM_CAST_MAC                         = 0x00000303
	CKM_CAST_MAC_GENERAL                 = 0x00000304
	CKM_CAST_CBC_PAD                     = 0x00000305
	CKM_CAST3_KEY_GEN                    = 0x00000310
	CKM_CAST3_ECB                        = 0x00000311
	CKM_CAST3_CBC                        = 0x00000312
	CKM_CAST3_MAC                        = 0x00000313
	CKM_CAST3_MAC_GENERAL                = 0x00000314
	CKM_CAST3_CBC_PAD                    = 0x00000315
	CKM_CAST5_KEY_GEN                    = 0x00000320
	CKM_CAST128_KEY_GEN                  = 0x00000320
	CKM_CAST5_ECB                        = 0x00000321
	CKM_CAST128_ECB                      = 0x00000321
	CKM_CAST5_CBC                        = 0x00000322 // Deprecated
	CKM_CAST128_CBC                      = 0x00000322
	CKM_CAST5_MAC                        = 0x00000323 // Deprecated
	CKM_CAST128_MAC                      = 0x00000323
	CKM_CAST5_MAC_GENERAL                = 0x00000324 // Deprecated
	CKM_CAST128_MAC_GENERAL              = 0x00000324
	CKM_CAST5_CBC_PAD                    = 0x00000325 // Deprecated
	CKM_CAST128_CBC_PAD                  = 0x00000325
	CKM_RC5_KEY_GEN                      = 0x00000330
	CKM_RC5_ECB                          = 0x00000331
	CKM_RC5_CBC                          = 0x00000332
	CKM_RC5_MAC                          = 0x00000333
	CKM_RC5_MAC_GENERAL                  = 0x00000334
	CKM_RC5_CBC_PAD                      = 0x00000335
	CKM_IDEA_KEY_GEN                     = 0x00000340
	CKM_IDEA_ECB                         = 0x00000341
	CKM_IDEA_CBC                         = 0x00000342
	CKM_IDEA_MAC                         = 0x00000343
	CKM_IDEA_MAC_GENERAL                 = 0x00000344
	CKM_IDEA_CBC_PAD                     = 0x00000345
	CKM_GENERIC_SECRET_KEY_GEN           = 0x00000350
	CKM_CONCATENATE_BASE_AND_KEY         = 0x00000360
	CKM_CONCATENATE_BASE_AND_DATA        = 0x00000362
	CKM_CONCATENATE_DATA_AND_BASE        = 0x00000363
	CKM_XOR_BASE_AND_DATA                = 0x00000364
	CKM_EXTRACT_KEY_FROM_KEY             = 0x00000365
	CKM_SSL3_PRE_MASTER_KEY_GEN          = 0x00000370
	CKM_SSL3_MASTER_KEY_DERIVE           = 0x00000371
	CKM_SSL3_KEY_AND_MAC_DERIVE          = 0x00000372
	CKM_SSL3_MASTER_KEY_DERIVE_DH        = 0x00000373
	CKM_TLS_PRE_MASTER_KEY_GEN           = 0x00000374
	CKM_TLS_MASTER_KEY_DERIVE            = 0x00000375
	CKM_TLS_KEY_AND_MAC_DERIVE           = 0x00000376
	CKM_TLS_MASTER_KEY_DERIVE_DH         = 0x00000377
	CKM_TLS_PRF                          = 0x00000378
	CKM_SSL3_MD5_MAC                     = 0x00000380
	CKM_SSL3_SHA1_MAC                    = 0x00000381
	CKM_MD5_KEY_DERIVATION               = 0x00000390
	CKM_MD2_KEY_DERIVATION               = 0x00000391
	CKM_SHA1_KEY_DERIVATION              = 0x00000392
	CKM_SHA256_KEY_DERIVATION            = 0x00000393
	CKM_SHA384_KEY_DERIVATION            = 0x00000394
	CKM_SHA512_KEY_DERIVATION            = 0x00000395
	CKM_SHA224_KEY_DERIVATION            = 0x00000396
	CKM_SHA3_256_KEY_DERIVE              = 0x00000397
	CKM_SHA3_224_KEY_DERIVE              = 0x00000398
	CKM_SHA3_384_KEY_DERIVE              = 0x00000399
	CKM_SHA3_512_KEY_DERIVE              = 0x0000039A
	CKM_SHAKE_128_KEY_DERIVE             = 0x0000039B
	CKM_SHAKE_256_KEY_DERIVE             = 0x0000039C
	CKM_PBE_MD2_DES_CBC                  = 0x000003A0
	CKM_PBE_MD5_DES_CBC                  = 0x000003A1
	CKM_PBE_MD5_CAST_CBC                 = 0x000003A2
	CKM_PBE_MD5_CAST3_CBC                = 0x000003A3
	CKM_PBE_MD5_CAST5_CBC                = 0x000003A4 // Deprecated
	CKM_PBE_MD5_CAST128_CBC              = 0x000003A4
	CKM_PBE_SHA1_CAST5_CBC               = 0x000003A5 // Deprecated
	CKM_PBE_SHA1_CAST128_CBC             = 0x000003A5
	CKM_PBE_SHA1_RC4_128                 = 0x000003A6
	CKM_PBE_SHA1_RC4_40                  = 0x000003A7
	CKM_PBE_SHA1_DES3_EDE_CBC            = 0x000003A8
	CKM_PBE_SHA1_DES2_EDE_CBC            = 0x000003A9
	CKM_PBE_SHA1_RC2_128_CBC             = 0x000003AA
	CKM_PBE_SHA1_RC2_40_CBC              = 0x000003AB
	CKM_PKCS5_PBKD2                      = 0x000003B0
	CKM_PBA_SHA1_WITH_SHA1_HMAC          = 0x000003C0
	CKM_WTLS_PRE_MASTER_KEY_GEN          = 0x000003D0
	CKM_WTLS_MASTER_KEY_DERIVE           = 0x000003D1
	CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC    = 0x000003D2
	CKM_WTLS_PRF                         = 0x000003D3
	CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE   = 0x000003D4
	CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE   = 0x000003D5
	CKM_TLS10_MAC_SERVER                 = 0x000003D6
	CKM_TLS10_MAC_CLIENT                 = 0x000003D7
	CKM_TLS12_MAC                        = 0x000003D8
	CKM_TLS12_KDF                        = 0x000003D9
	CKM_TLS12_MASTER_KEY_DERIVE          = 0x000003E0
	CKM_TLS12_KEY_AND_MAC_DERIVE         = 0x000003E1
	CKM_TLS12_MASTER_KEY_DERIVE_DH       = 0x000003E2
	CKM_TLS12_KEY_SAFE_DERIVE            = 0x000003E3
	CKM_TLS_MAC                          = 0x000003E4
	CKM_TLS_KDF                          = 0x000003E5
	CKM_KEY_WRAP_LYNKS                   = 0x00000400
	CKM_KEY_WRAP_SET_OAEP                = 0x00000401
	CKM_CMS_SIG                          = 0x00000500
	CKM_KIP_DERIVE                       = 0x00000510
	CKM_KIP_WRAP                         = 0x00000511
	CKM_KIP_MAC                          = 0x00000512
	CKM_CAMELLIA_KEY_GEN                 = 0x00000550
	CKM_CAMELLIA_ECB                     = 0x00000551
	CKM_CAMELLIA_CBC                     = 0x00000552
	CKM_CAMELLIA_MAC                     = 0x00000553
	CKM_CAMELLIA_MAC_GENERAL             = 0x00000554
	CKM_CAMELLIA_CBC_PAD                 = 0x00000555
	CKM_CAMELLIA_ECB_ENCRYPT_DATA        = 0x00000556
	CKM_CAMELLIA_CBC_ENCRYPT_DATA        = 0x00000557
	CKM_CAMELLIA_CTR                     = 0x00000558
	CKM_ARIA_KEY_GEN                     = 0x00000560
	CKM_ARIA_ECB                         = 0x00000561
	CKM_ARIA_CBC                         = 0x00000562
	CKM_ARIA_MAC                         = 0x00000563
	CKM_ARIA_MAC_GENERAL                 = 0x00000564
	CKM_ARIA_CBC_PAD                     = 0x00000565
	CKM_ARIA_ECB_ENCRYPT_DATA            = 0x00000566
	CKM_ARIA_CBC_ENCRYPT_DATA            = 0x00000567
	CKM_SEED_KEY_GEN                     = 0x00000650
	CKM_SEED_ECB                         = 0x00000651
	CKM_SEED_CBC                         = 0x00000652
	CKM_SEED_MAC                         = 0x00000653
	CKM_SEED_MAC_GENERAL                 = 0x00000654
	CKM_SEED_CBC_PAD                     = 0x00000655
	CKM_SEED_ECB_ENCRYPT_DATA            = 0x00000656
	CKM_SEED_CBC_ENCRYPT_DATA            = 0x00000657
	CKM_SKIPJACK_KEY_GEN                 = 0x00001000
	CKM_SKIPJACK_ECB64                   = 0x00001001
	CKM_SKIPJACK_CBC64                   = 0x00001002
	CKM_SKIPJACK_OFB64                   = 0x00001003
	CKM_SKIPJACK_CFB64                   = 0x00001004
	CKM_SKIPJACK_CFB32                   = 0x00001005
	CKM_SKIPJACK_CFB16                   = 0x00001006
	CKM_SKIPJACK_CFB8                    = 0x00001007
	CKM_SKIPJACK_WRAP                    = 0x00001008
	CKM_SKIPJACK_PRIVATE_WRAP            = 0x00001009
	CKM_SKIPJACK_RELAYX                  = 0x0000100a
	CKM_KEA_KEY_PAIR_GEN                 = 0x00001010
	CKM_KEA_KEY_DERIVE                   = 0x00001011
	CKM_KEA_DERIVE                       = 0x00001012
	CKM_FORTEZZA_TIMESTAMP               = 0x00001020
	CKM_BATON_KEY_GEN                    = 0x00001030
	CKM_BATON_ECB128                     = 0x00001031
	CKM_BATON_ECB96                      = 0x00001032
	CKM_BATON_CBC128                     = 0x00001033
	CKM_BATON_COUNTER                    = 0x00001034
	CKM_BATON_SHUFFLE                    = 0x00001035
	CKM_BATON_WRAP                       = 0x00001036
	CKM_ECDSA_KEY_PAIR_GEN               = 0x00001040 // Deprecated
	CKM_EC_KEY_PAIR_GEN                  = 0x00001040
	CKM_ECDSA                            = 0x00001041
	CKM_ECDSA_SHA1                       = 0x00001042
	CKM_ECDSA_SHA224                     = 0x00001043
	CKM_ECDSA_SHA256                     = 0x00001044
	CKM_ECDSA_SHA384                     = 0x00001045
	CKM_ECDSA_SHA512                     = 0x00001046
	CKM_ECDH1_DERIVE                     = 0x00001050
	CKM_ECDH1_COFACTOR_DERIVE            = 0x00001051
	CKM_ECMQV_DERIVE                     = 0x00001052
	CKM_ECDH_AES_KEY_WRAP                = 0x00001053
	CKM_RSA_AES_KEY_WRAP                 = 0x00001054
	CKM_JUNIPER_KEY_GEN                  = 0x00001060
	CKM_JUNIPER_ECB128                   = 0x00001061
	CKM_JUNIPER_CBC128                   = 0x00001062
	CKM_JUNIPER_COUNTER                  = 0x00001063
	CKM_JUNIPER_SHUFFLE                  = 0x00001064
	CKM_JUNIPER_WRAP                     = 0x00001065
	CKM_FASTHASH                         = 0x00001070
	CKM_AES_KEY_GEN                      = 0x00001080
	CKM_AES_ECB                          = 0x00001081
	CKM_AES_CBC                          = 0x00001082
	CKM_AES_MAC                          = 0x00001083
	CKM_AES_MAC_GENERAL                  = 0x00001084
	CKM_AES_CBC_PAD                      = 0x00001085
	CKM_AES_CTR                          = 0x00001086
	CKM_AES_GCM                          = 0x00001087
	CKM_AES_CCM                          = 0x00001088
	CKM_AES_CTS                          = 0x00001089
	CKM_AES_CMAC                         = 0x0000108A
	CKM_AES_CMAC_GENERAL                 = 0x0000108B
	CKM_AES_XCBC_MAC                     = 0x0000108C
	CKM_AES_XCBC_MAC_96                  = 0x0000108D
	CKM_AES_GMAC                         = 0x0000108E
	CKM_BLOWFISH_KEY_GEN                 = 0x00001090
	CKM_BLOWFISH_CBC                     = 0x00001091
	CKM_TWOFISH_KEY_GEN                  = 0x00001092
	CKM_TWOFISH_CBC                      = 0x00001093
	CKM_BLOWFISH_CBC_PAD                 = 0x00001094
	CKM_TWOFISH_CBC_PAD                  = 0x00001095
	CKM_DES_ECB_ENCRYPT_DATA             = 0x00001100
	CKM_DES_CBC_ENCRYPT_DATA             = 0x00001101
	CKM_DES3_ECB_ENCRYPT_DATA            = 0x00001102
	CKM_DES3_CBC_ENCRYPT_DATA            = 0x00001103
	CKM_AES_ECB_ENCRYPT_DATA             = 0x00001104
	CKM_AES_CBC_ENCRYPT_DATA             = 0x00001105
	CKM_GOSTR3410_KEY_PAIR_GEN           = 0x00001200
	CKM_GOSTR3410                        = 0x00001201
	CKM_GOSTR3410_WITH_GOSTR3411         = 0x00001202
	CKM_GOSTR3410_KEY_WRAP               = 0x00001203
	CKM_GOSTR3410_DERIVE                 = 0x00001204
	CKM_GOSTR3411                        = 0x00001210
	CKM_GOSTR3411_HMAC                   = 0x00001211
	CKM_GOST28147_KEY_GEN                = 0x00001220
	CKM_GOST28147_ECB                    = 0x00001221
	CKM_GOST28147                        = 0x00001222
	CKM_GOST28147_MAC                    = 0x00001223
	CKM_GOST28147_KEY_WRAP               = 0x00001224
	CKM_DSA_PARAMETER_GEN                = 0x00002000
	CKM_DH_PKCS_PARAMETER_GEN            = 0x00002001
	CKM_X9_42_DH_PARAMETER_GEN           = 0x00002002
	CKM_DSA_PROBABLISTIC_PARAMETER_GEN   = 0x00002003
	CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN   = 0x00002004
	CKM_AES_OFB                          = 0x00002104
	CKM_AES_CFB64                        = 0x00002105
	CKM_AES_CFB8                         = 0x00002106
	CKM_AES_CFB128                       = 0x00002107
	CKM_AES_CFB1                         = 0x00002108
	CKM_AES_KEY_WRAP                     = 0x00002109
	CKM_AES_KEY_WRAP_PAD                 = 0x0000210A
	CKM_RSA_PKCS_TPM_1_1                 = 0x00004001
	CKM_RSA_PKCS_OAEP_TPM_1_1            = 0x00004002
	CKM_VENDOR_DEFINED                   = 0x80000000
	CKF_HW                               = 0x00000001
	CKF_ENCRYPT                          = 0x00000100
	CKF_DECRYPT                          = 0x00000200
	CKF_DIGEST                           = 0x00000400
	CKF_SIGN                             = 0x00000800
	CKF_SIGN_RECOVER                     = 0x00001000
	CKF_VERIFY                           = 0x00002000
	CKF_VERIFY_RECOVER                   = 0x00004000
	CKF_GENERATE                         = 0x00008000
	CKF_GENERATE_KEY_PAIR                = 0x00010000
	CKF_WRAP                             = 0x00020000
	CKF_UNWRAP                           = 0x00040000
	CKF_DERIVE                           = 0x00080000
	CKF_EC_F_P                           = 0x00100000
	CKF_EC_F_2M                          = 0x00200000
	CKF_EC_ECPARAMETERS                  = 0x00400000
	CKF_EC_NAMEDCURVE                    = 0x00800000
	CKF_EC_UNCOMPRESS                    = 0x01000000
	CKF_EC_COMPRESS                      = 0x02000000
	CKF_EXTENSION                        = 0x80000000
	CKR_OK                               = 0x00000000
	CKR_CANCEL                           = 0x00000001
	CKR_HOST_MEMORY                      = 0x00000002
	CKR_SLOT_ID_INVALID                  = 0x00000003
	CKR_GENERAL_ERROR                    = 0x00000005
	CKR_FUNCTION_FAILED                  = 0x00000006
	CKR_ARGUMENTS_BAD                    = 0x00000007
	CKR_NO_EVENT                         = 0x00000008
	CKR_NEED_TO_CREATE_THREADS           = 0x00000009
	CKR_CANT_LOCK                        = 0x0000000A
	CKR_ATTRIBUTE_READ_ONLY              = 0x00000010
	CKR_ATTRIBUTE_SENSITIVE              = 0x00000011
	CKR_ATTRIBUTE_TYPE_INVALID           = 0x00000012
	CKR_ATTRIBUTE_VALUE_INVALID          = 0x00000013
	CKR_ACTION_PROHIBITED                = 0x0000001B
	CKR_DATA_INVALID                     = 0x00000020
	CKR_DATA_LEN_RANGE                   = 0x00000021
	CKR_DEVICE_ERROR                     = 0x00000030
	CKR_DEVICE_MEMORY                    = 0x00000031
	CKR_DEVICE_REMOVED                   = 0x00000032
	CKR_ENCRYPTED_DATA_INVALID           = 0x00000040
	CKR_ENCRYPTED_DATA_LEN_RANGE         = 0x00000041
	CKR_FUNCTION_CANCELED                = 0x00000050
	CKR_FUNCTION_NOT_PARALLEL            = 0x00000051
	CKR_FUNCTION_NOT_SUPPORTED           = 0x00000054
	CKR_KEY_HANDLE_INVALID               = 0x00000060
	CKR_KEY_SIZE_RANGE                   = 0x00000062
	CKR_KEY_TYPE_INCONSISTENT            = 0x00000063
	CKR_KEY_NOT_NEEDED                   = 0x00000064
	CKR_KEY_CHANGED                      = 0x00000065
	CKR_KEY_NEEDED                       = 0x00000066
	CKR_KEY_INDIGESTIBLE                 = 0x00000067
	CKR_KEY_FUNCTION_NOT_PERMITTED       = 0x00000068
	CKR_KEY_NOT_WRAPPABLE                = 0x00000069
	CKR_KEY_UNEXTRACTABLE                = 0x0000006A
	CKR_MECHANISM_INVALID                = 0x00000070
	CKR_MECHANISM_PARAM_INVALID          = 0x00000071
	CKR_OBJECT_HANDLE_INVALID            = 0x00000082
	CKR_OPERATION_ACTIVE                 = 0x00000090
	CKR_OPERATION_NOT_INITIALIZED        = 0x00000091
	CKR_PIN_INCORRECT                    = 0x000000A0
	CKR_PIN_INVALID                      = 0x000000A1
	CKR_PIN_LEN_RANGE                    = 0x000000A2
	CKR_PIN_EXPIRED                      = 0x000000A3
	CKR_PIN_LOCKED                       = 0x000000A4
	CKR_SESSION_CLOSED                   = 0x000000B0
	CKR_SESSION_COUNT                    = 0x000000B1
	CKR_SESSION_HANDLE_INVALID           = 0x000000B3
	CKR_SESSION_PARALLEL_NOT_SUPPORTED   = 0x000000B4
	CKR_SESSION_READ_ONLY                = 0x000000B5
	CKR_SESSION_EXISTS                   = 0x000000B6
	CKR_SESSION_READ_ONLY_EXISTS         = 0x000000B7
	CKR_SESSION_READ_WRITE_SO_EXISTS     = 0x000000B8
	CKR_SIGNATURE_INVALID                = 0x000000C0
	CKR_SIGNATURE_LEN_RANGE              = 0x000000C1
	CKR_TEMPLATE_INCOMPLETE              = 0x000000D0
	CKR_TEMPLATE_INCONSISTENT            = 0x000000D1
	CKR_TOKEN_NOT_PRESENT                = 0x000000E0
	CKR_TOKEN_NOT_RECOGNIZED             = 0x000000E1
	CKR_TOKEN_WRITE_PROTECTED            = 0x000000E2
	CKR_UNWRAPPING_KEY_HANDLE_INVALID    = 0x000000F0
	CKR_UNWRAPPING_KEY_SIZE_RANGE        = 0x000000F1
	CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x000000F2
	CKR_USER_ALREADY_LOGGED_IN           = 0x00000100
	CKR_USER_NOT_LOGGED_IN               = 0x00000101
	CKR_USER_PIN_NOT_INITIALIZED         = 0x00000102
	CKR_USER_TYPE_INVALID                = 0x00000103
	CKR_USER_ANOTHER_ALREADY_LOGGED_IN   = 0x00000104
	CKR_USER_TOO_MANY_TYPES              = 0x00000105
	CKR_WRAPPED_KEY_INVALID              = 0x00000110
	CKR_WRAPPED_KEY_LEN_RANGE            = 0x00000112
	CKR_WRAPPING_KEY_HANDLE_INVALID      = 0x00000113
	CKR_WRAPPING_KEY_SIZE_RANGE          = 0x00000114
	CKR_WRAPPING_KEY_TYPE_INCONSISTENT   = 0x00000115
	CKR_RANDOM_SEED_NOT_SUPPORTED        = 0x00000120
	CKR_RANDOM_NO_RNG                    = 0x00000121
	CKR_DOMAIN_PARAMS_INVALID            = 0x00000130
	CKR_CURVE_NOT_SUPPORTED              = 0x00000140
	CKR_BUFFER_TOO_SMALL                 = 0x00000150
	CKR_SAVED_STATE_INVALID              = 0x00000160
	CKR_INFORMATION_SENSITIVE            = 0x00000170
	CKR_STATE_UNSAVEABLE                 = 0x00000180
	CKR_CRYPTOKI_NOT_INITIALIZED         = 0x00000190
	CKR_CRYPTOKI_ALREADY_INITIALIZED     = 0x00000191
	CKR_MUTEX_BAD                        = 0x000001A0
	CKR_MUTEX_NOT_LOCKED                 = 0x000001A1
	CKR_NEW_PIN_MODE                     = 0x000001B0
	CKR_NEXT_OTP                         = 0x000001B1
	CKR_EXCEEDED_MAX_ITERATIONS          = 0x000001B5
	CKR_FIPS_SELF_TEST_FAILED            = 0x000001B6
	CKR_LIBRARY_LOAD_FAILED              = 0x000001B7
	CKR_PIN_TOO_WEAK                     = 0x000001B8
	CKR_PUBLIC_KEY_INVALID               = 0x000001B9
	CKR_FUNCTION_REJECTED                = 0x00000200
	CKR_VENDOR_DEFINED                   = 0x80000000
	CKF_LIBRARY_CANT_CREATE_OS_THREADS   = 0x00000001
	CKF_OS_LOCKING_OK                    = 0x00000002
	CKF_DONT_BLOCK                       = 1
	CKG_MGF1_SHA1                        = 0x00000001
	CKG_MGF1_SHA256                      = 0x00000002
	CKG_MGF1_SHA384                      = 0x00000003
	CKG_MGF1_SHA512                      = 0x00000004
	CKG_MGF1_SHA224                      = 0x00000005
	CKZ_DATA_SPECIFIED                   = 0x00000001
	CKD_NULL                             = 0x00000001
	CKD_SHA1_KDF                         = 0x00000002
	CKD_SHA1_KDF_ASN1                    = 0x00000003
	CKD_SHA1_KDF_CONCATENATE             = 0x00000004
	CKD_SHA224_KDF                       = 0x00000005
	CKD_SHA256_KDF                       = 0x00000006
	CKD_SHA384_KDF                       = 0x00000007
	CKD_SHA512_KDF                       = 0x00000008
	CKD_CPDIVERSIFY_KDF                  = 0x00000009
	CKD_SHA3_224_KDF                     = 0x0000000A
	CKD_SHA3_256_KDF                     = 0x0000000B
	CKD_SHA3_384_KDF                     = 0x0000000C
	CKD_SHA3_512_KDF                     = 0x0000000D
	CKP_PKCS5_PBKD2_HMAC_SHA1            = 0x00000001
	CKP_PKCS5_PBKD2_HMAC_GOSTR3411       = 0x00000002
	CKP_PKCS5_PBKD2_HMAC_SHA224          = 0x00000003
	CKP_PKCS5_PBKD2_HMAC_SHA256          = 0x00000004
	CKP_PKCS5_PBKD2_HMAC_SHA384          = 0x00000005
	CKP_PKCS5_PBKD2_HMAC_SHA512          = 0x00000006
	CKP_PKCS5_PBKD2_HMAC_SHA512_224      = 0x00000007
	CKP_PKCS5_PBKD2_HMAC_SHA512_256      = 0x00000008
	CKZ_SALT_SPECIFIED                   = 0x00000001
	CK_OTP_VALUE                         = 0
	CK_OTP_PIN                           = 1
	CK_OTP_CHALLENGE                     = 2
	CK_OTP_TIME                          = 3
	CK_OTP_COUNTER                       = 4
	CK_OTP_FLAGS                         = 5
	CK_OTP_OUTPUT_LENGTH                 = 6
	CK_OTP_OUTPUT_FORMAT                 = 7
	CKF_NEXT_OTP                         = 0x00000001
	CKF_EXCLUDE_TIME                     = 0x00000002
	CKF_EXCLUDE_COUNTER                  = 0x00000004
	CKF_EXCLUDE_CHALLENGE                = 0x00000008
	CKF_EXCLUDE_PIN                      = 0x00000010
	CKF_USER_FRIENDLY_OTP                = 0x00000020
)

// Error represents an PKCS#11 error.
type Error uint

func (e Error) Error() string {
	return fmt.Sprintf("pkcs11: 0x%X: %s", uint(e), strerror[uint(e)])
}

var strerror = map[uint]string{
	0x00000000: "CKR_OK",
	0x00000001: "CKR_CANCEL",
	0x00000002: "CKR_HOST_MEMORY",
	0x00000003: "CKR_SLOT_ID_INVALID",
	0x00000005: "CKR_GENERAL_ERROR",
	0x00000006: "CKR_FUNCTION_FAILED",
	0x00000007: "CKR_ARGUMENTS_BAD",
	0x00000008: "CKR_NO_EVENT",
	0x00000009: "CKR_NEED_TO_CREATE_THREADS",
	0x0000000A: "CKR_CANT_LOCK",
	0x00000010: "CKR_ATTRIBUTE_READ_ONLY",
	0x00000011: "CKR_ATTRIBUTE_SENSITIVE",
	0x00000012: "CKR_ATTRIBUTE_TYPE_INVALID",
	0x00000013: "CKR_ATTRIBUTE_VALUE_INVALID",
	0x00000020: "CKR_DATA_INVALID",
	0x00000021: "CKR_DATA_LEN_RANGE",
	0x00000030: "CKR_DEVICE_ERROR",
	0x00000031: "CKR_DEVICE_MEMORY",
	0x00000032: "CKR_DEVICE_REMOVED",
	0x00000040: "CKR_ENCRYPTED_DATA_INVALID",
	0x00000041: "CKR_ENCRYPTED_DATA_LEN_RANGE",
	0x00000050: "CKR_FUNCTION_CANCELED",
	0x00000051: "CKR_FUNCTION_NOT_PARALLEL",
	0x00000054: "CKR_FUNCTION_NOT_SUPPORTED",
	0x00000060: "CKR_KEY_HANDLE_INVALID",
	0x00000062: "CKR_KEY_SIZE_RANGE",
	0x00000063: "CKR_KEY_TYPE_INCONSISTENT",
	0x00000064: "CKR_KEY_NOT_NEEDED",
	0x00000065: "CKR_KEY_CHANGED",
	0x00000066: "CKR_KEY_NEEDED",
	0x00000067: "CKR_KEY_INDIGESTIBLE",
	0x00000068: "CKR_KEY_FUNCTION_NOT_PERMITTED",
	0x00000069: "CKR_KEY_NOT_WRAPPABLE",
	0x0000006A: "CKR_KEY_UNEXTRACTABLE",
	0x00000070: "CKR_MECHANISM_INVALID",
	0x00000071: "CKR_MECHANISM_PARAM_INVALID",
	0x00000082: "CKR_OBJECT_HANDLE_INVALID",
	0x00000090: "CKR_OPERATION_ACTIVE",
	0x00000091: "CKR_OPERATION_NOT_INITIALIZED",
	0x000000A0: "CKR_PIN_INCORRECT",
	0x000000A1: "CKR_PIN_INVALID",
	0x000000A2: "CKR_PIN_LEN_RANGE",
	0x000000A3: "CKR_PIN_EXPIRED",
	0x000000A4: "CKR_PIN_LOCKED",
	0x000000B0: "CKR_SESSION_CLOSED",
	0x000000B1: "CKR_SESSION_COUNT",
	0x000000B3: "CKR_SESSION_HANDLE_INVALID",
	0x000000B4: "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
	0x000000B5: "CKR_SESSION_READ_ONLY",
	0x000000B6: "CKR_SESSION_EXISTS",
	0x000000B7: "CKR_SESSION_READ_ONLY_EXISTS",
	0x000000B8: "CKR_SESSION_READ_WRITE_SO_EXISTS",
	0x000000C0: "CKR_SIGNATURE_INVALID",
	0x000000C1: "CKR_SIGNATURE_LEN_RANGE",
	0x000000D0: "CKR_TEMPLATE_INCOMPLETE",
	0x000000D1: "CKR_TEMPLATE_INCONSISTENT",
	0x000000E0: "CKR_TOKEN_NOT_PRESENT",
	0x000000E1: "CKR_TOKEN_NOT_RECOGNIZED",
	0x000000E2: "CKR_TOKEN_WRITE_PROTECTED",
	0x000000F0: "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
	0x000000F1: "CKR_UNWRAPPING_KEY_SIZE_RANGE",
	0x000000F2: "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
	0x00000100: "CKR_USER_ALREADY_LOGGED_IN",
	0x00000101: "CKR_USER_NOT_LOGGED_IN",
	0x00000102: "CKR_USER_PIN_NOT_INITIALIZED",
	0x00000103: "CKR_USER_TYPE_INVALID",
	0x00000104: "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
	0x00000105: "CKR_USER_TOO_MANY_TYPES",
	0x00000110: "CKR_WRAPPED_KEY_INVALID",
	0x00000112: "CKR_WRAPPED_KEY_LEN_RANGE",
	0x00000113: "CKR_WRAPPING_KEY_HANDLE_INVALID",
	0x00000114: "CKR_WRAPPING_KEY_SIZE_RANGE",
	0x00000115: "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
	0x00000120: "CKR_RANDOM_SEED_NOT_SUPPORTED",
	0x00000121: "CKR_RANDOM_NO_RNG",
	0x00000130: "CKR_DOMAIN_PARAMS_INVALID",
	0x00000150: "CKR_BUFFER_TOO_SMALL",
	0x00000160: "CKR_SAVED_STATE_INVALID",
	0x00000170: "CKR_INFORMATION_SENSITIVE",
	0x00000180: "CKR_STATE_UNSAVEABLE",
	0x00000190: "CKR_CRYPTOKI_NOT_INITIALIZED",
	0x00000191: "CKR_CRYPTOKI_ALREADY_INITIALIZED",
	0x000001A0: "CKR_MUTEX_BAD",
	0x000001A1: "CKR_MUTEX_NOT_LOCKED",
	0x000001B0: "CKR_NEW_PIN_MODE",
	0x000001B1: "CKR_NEXT_OTP",
	0x00000200: "CKR_FUNCTION_REJECTED",
	0x80000000: "CKR_VENDOR_DEFINED",
}

var KnownMechanisms = []uint64{
	CKM_RSA_PKCS_KEY_PAIR_GEN,
	CKM_RSA_PKCS,
	CKM_RSA_9796,
	CKM_RSA_X_509,
	CKM_MD2_RSA_PKCS,
	CKM_MD5_RSA_PKCS,
	CKM_SHA1_RSA_PKCS,
	CKM_RIPEMD128_RSA_PKCS,
	CKM_RIPEMD160_RSA_PKCS,
	CKM_RSA_PKCS_OAEP,
	CKM_RSA_X9_31_KEY_PAIR_GEN,
	CKM_RSA_X9_31,
	CKM_SHA1_RSA_X9_31,
	CKM_RSA_PKCS_PSS,
	CKM_SHA1_RSA_PKCS_PSS,
	CKM_DSA_KEY_PAIR_GEN,
	CKM_DSA,
	CKM_DSA_SHA1,
	CKM_DSA_SHA224,
	CKM_DSA_SHA256,
	CKM_DSA_SHA384,
	CKM_DSA_SHA512,
	CKM_DSA_SHA3_224,
	CKM_DSA_SHA3_256,
	CKM_DSA_SHA3_384,
	CKM_DSA_SHA3_512,
	CKM_DH_PKCS_KEY_PAIR_GEN,
	CKM_DH_PKCS_DERIVE,
	CKM_X9_42_DH_KEY_PAIR_GEN,
	CKM_X9_42_DH_DERIVE,
	CKM_X9_42_DH_HYBRID_DERIVE,
	CKM_X9_42_MQV_DERIVE,
	CKM_SHA256_RSA_PKCS,
	CKM_SHA384_RSA_PKCS,
	CKM_SHA512_RSA_PKCS,
	CKM_SHA256_RSA_PKCS_PSS,
	CKM_SHA384_RSA_PKCS_PSS,
	CKM_SHA512_RSA_PKCS_PSS,
	CKM_SHA224_RSA_PKCS,
	CKM_SHA224_RSA_PKCS_PSS,
	CKM_SHA512_224,
	CKM_SHA512_224_HMAC,
	CKM_SHA512_224_HMAC_GENERAL,
	CKM_SHA512_224_KEY_DERIVATION,
	CKM_SHA512_256,
	CKM_SHA512_256_HMAC,
	CKM_SHA512_256_HMAC_GENERAL,
	CKM_SHA512_256_KEY_DERIVATION,
	CKM_SHA512_T,
	CKM_SHA512_T_HMAC,
	CKM_SHA512_T_HMAC_GENERAL,
	CKM_SHA512_T_KEY_DERIVATION,
	CKM_SHA3_256_RSA_PKCS,
	CKM_SHA3_384_RSA_PKCS,
	CKM_SHA3_512_RSA_PKCS,
	CKM_SHA3_256_RSA_PKCS_PSS,
	CKM_SHA3_384_RSA_PKCS_PSS,
	CKM_SHA3_512_RSA_PKCS_PSS,
	CKM_SHA3_224_RSA_PKCS,
	CKM_SHA3_224_RSA_PKCS_PSS,
	CKM_RC2_KEY_GEN,
	CKM_RC2_ECB,
	CKM_RC2_CBC,
	CKM_RC2_MAC,
	CKM_RC2_MAC_GENERAL,
	CKM_RC2_CBC_PAD,
	CKM_RC4_KEY_GEN,
	CKM_RC4,
	CKM_DES_KEY_GEN,
	CKM_DES_ECB,
	CKM_DES_CBC,
	CKM_DES_MAC,
	CKM_DES_MAC_GENERAL,
	CKM_DES_CBC_PAD,
	CKM_DES2_KEY_GEN,
	CKM_DES3_KEY_GEN,
	CKM_DES3_ECB,
	CKM_DES3_CBC,
	CKM_DES3_MAC,
	CKM_DES3_MAC_GENERAL,
	CKM_DES3_CBC_PAD,
	CKM_DES3_CMAC_GENERAL,
	CKM_DES3_CMAC,
	CKM_CDMF_KEY_GEN,
	CKM_CDMF_ECB,
	CKM_CDMF_CBC,
	CKM_CDMF_MAC,
	CKM_CDMF_MAC_GENERAL,
	CKM_CDMF_CBC_PAD,
	CKM_DES_OFB64,
	CKM_DES_OFB8,
	CKM_DES_CFB64,
	CKM_DES_CFB8,
	CKM_MD2,
	CKM_MD2_HMAC,
	CKM_MD2_HMAC_GENERAL,
	CKM_MD5,
	CKM_MD5_HMAC,
	CKM_MD5_HMAC_GENERAL,
	CKM_SHA_1,
	CKM_SHA_1_HMAC,
	CKM_SHA_1_HMAC_GENERAL,
	CKM_RIPEMD128,
	CKM_RIPEMD128_HMAC,
	CKM_RIPEMD128_HMAC_GENERAL,
	CKM_RIPEMD160,
	CKM_RIPEMD160_HMAC,
	CKM_RIPEMD160_HMAC_GENERAL,
	CKM_SHA256,
	CKM_SHA256_HMAC,
	CKM_SHA256_HMAC_GENERAL,
	CKM_SHA224,
	CKM_SHA224_HMAC,
	CKM_SHA224_HMAC_GENERAL,
	CKM_SHA384,
	CKM_SHA384_HMAC,
	CKM_SHA384_HMAC_GENERAL,
	CKM_SHA512,
	CKM_SHA512_HMAC,
	CKM_SHA512_HMAC_GENERAL,
	CKM_SECURID_KEY_GEN,
	CKM_SECURID,
	CKM_HOTP_KEY_GEN,
	CKM_HOTP,
	CKM_ACTI,
	CKM_ACTI_KEY_GEN,
	CKM_SHA3_256,
	CKM_SHA3_256_HMAC,
	CKM_SHA3_256_HMAC_GENERAL,
	CKM_SHA3_256_KEY_GEN,
	CKM_SHA3_224,
	CKM_SHA3_224_HMAC,
	CKM_SHA3_224_HMAC_GENERAL,
	CKM_SHA3_224_KEY_GEN,
	CKM_SHA3_384,
	CKM_SHA3_384_HMAC,
	CKM_SHA3_384_HMAC_GENERAL,
	CKM_SHA3_384_KEY_GEN,
	CKM_SHA3_512,
	CKM_SHA3_512_HMAC,
	CKM_SHA3_512_HMAC_GENERAL,
	CKM_SHA3_512_KEY_GEN,
	CKM_CAST_KEY_GEN,
	CKM_CAST_ECB,
	CKM_CAST_CBC,
	CKM_CAST_MAC,
	CKM_CAST_MAC_GENERAL,
	CKM_CAST_CBC_PAD,
	CKM_CAST3_KEY_GEN,
	CKM_CAST3_ECB,
	CKM_CAST3_CBC,
	CKM_CAST3_MAC,
	CKM_CAST3_MAC_GENERAL,
	CKM_CAST3_CBC_PAD,
	CKM_CAST5_KEY_GEN,
	CKM_CAST128_KEY_GEN,
	CKM_CAST5_ECB,
	CKM_CAST128_ECB,
	CKM_CAST5_CBC,
	CKM_CAST128_CBC,
	CKM_CAST5_MAC,
	CKM_CAST128_MAC,
	CKM_CAST5_MAC_GENERAL,
	CKM_CAST128_MAC_GENERAL,
	CKM_CAST5_CBC_PAD,
	CKM_CAST128_CBC_PAD,
	CKM_RC5_KEY_GEN,
	CKM_RC5_ECB,
	CKM_RC5_CBC,
	CKM_RC5_MAC,
	CKM_RC5_MAC_GENERAL,
	CKM_RC5_CBC_PAD,
	CKM_IDEA_KEY_GEN,
	CKM_IDEA_ECB,
	CKM_IDEA_CBC,
	CKM_IDEA_MAC,
	CKM_IDEA_MAC_GENERAL,
	CKM_IDEA_CBC_PAD,
	CKM_GENERIC_SECRET_KEY_GEN,
	CKM_CONCATENATE_BASE_AND_KEY,
	CKM_CONCATENATE_BASE_AND_DATA,
	CKM_CONCATENATE_DATA_AND_BASE,
	CKM_XOR_BASE_AND_DATA,
	CKM_EXTRACT_KEY_FROM_KEY,
	CKM_SSL3_PRE_MASTER_KEY_GEN,
	CKM_SSL3_MASTER_KEY_DERIVE,
	CKM_SSL3_KEY_AND_MAC_DERIVE,
	CKM_SSL3_MASTER_KEY_DERIVE_DH,
	CKM_TLS_PRE_MASTER_KEY_GEN,
	CKM_TLS_MASTER_KEY_DERIVE,
	CKM_TLS_KEY_AND_MAC_DERIVE,
	CKM_TLS_MASTER_KEY_DERIVE_DH,
	CKM_TLS_PRF,
	CKM_SSL3_MD5_MAC,
	CKM_SSL3_SHA1_MAC,
	CKM_MD5_KEY_DERIVATION,
	CKM_MD2_KEY_DERIVATION,
	CKM_SHA1_KEY_DERIVATION,
	CKM_SHA256_KEY_DERIVATION,
	CKM_SHA384_KEY_DERIVATION,
	CKM_SHA512_KEY_DERIVATION,
	CKM_SHA224_KEY_DERIVATION,
	CKM_SHA3_256_KEY_DERIVE,
	CKM_SHA3_224_KEY_DERIVE,
	CKM_SHA3_384_KEY_DERIVE,
	CKM_SHA3_512_KEY_DERIVE,
	CKM_SHAKE_128_KEY_DERIVE,
	CKM_SHAKE_256_KEY_DERIVE,
	CKM_PBE_MD2_DES_CBC,
	CKM_PBE_MD5_DES_CBC,
	CKM_PBE_MD5_CAST_CBC,
	CKM_PBE_MD5_CAST3_CBC,
	CKM_PBE_MD5_CAST5_CBC,
	CKM_PBE_MD5_CAST128_CBC,
	CKM_PBE_SHA1_CAST5_CBC,
	CKM_PBE_SHA1_CAST128_CBC,
	CKM_PBE_SHA1_RC4_128,
	CKM_PBE_SHA1_RC4_40,
	CKM_PBE_SHA1_DES3_EDE_CBC,
	CKM_PBE_SHA1_DES2_EDE_CBC,
	CKM_PBE_SHA1_RC2_128_CBC,
	CKM_PBE_SHA1_RC2_40_CBC,
	CKM_PKCS5_PBKD2,
	CKM_PBA_SHA1_WITH_SHA1_HMAC,
	CKM_WTLS_PRE_MASTER_KEY_GEN,
	CKM_WTLS_MASTER_KEY_DERIVE,
	CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
	CKM_WTLS_PRF,
	CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
	CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
	CKM_TLS10_MAC_SERVER,
	CKM_TLS10_MAC_CLIENT,
	CKM_TLS12_MAC,
	CKM_TLS12_KDF,
	CKM_TLS12_MASTER_KEY_DERIVE,
	CKM_TLS12_KEY_AND_MAC_DERIVE,
	CKM_TLS12_MASTER_KEY_DERIVE_DH,
	CKM_TLS12_KEY_SAFE_DERIVE,
	CKM_TLS_MAC,
	CKM_TLS_KDF,
	CKM_KEY_WRAP_LYNKS,
	CKM_KEY_WRAP_SET_OAEP,
	CKM_CMS_SIG,
	CKM_KIP_DERIVE,
	CKM_KIP_WRAP,
	CKM_KIP_MAC,
	CKM_CAMELLIA_KEY_GEN,
	CKM_CAMELLIA_ECB,
	CKM_CAMELLIA_CBC,
	CKM_CAMELLIA_MAC,
	CKM_CAMELLIA_MAC_GENERAL,
	CKM_CAMELLIA_CBC_PAD,
	CKM_CAMELLIA_ECB_ENCRYPT_DATA,
	CKM_CAMELLIA_CBC_ENCRYPT_DATA,
	CKM_CAMELLIA_CTR,
	CKM_ARIA_KEY_GEN,
	CKM_ARIA_ECB,
	CKM_ARIA_CBC,
	CKM_ARIA_MAC,
	CKM_ARIA_MAC_GENERAL,
	CKM_ARIA_CBC_PAD,
	CKM_ARIA_ECB_ENCRYPT_DATA,
	CKM_ARIA_CBC_ENCRYPT_DATA,
	CKM_SEED_KEY_GEN,
	CKM_SEED_ECB,
	CKM_SEED_CBC,
	CKM_SEED_MAC,
	CKM_SEED_MAC_GENERAL,
	CKM_SEED_CBC_PAD,
	CKM_SEED_ECB_ENCRYPT_DATA,
	CKM_SEED_CBC_ENCRYPT_DATA,
	CKM_SKIPJACK_KEY_GEN,
	CKM_SKIPJACK_ECB64,
	CKM_SKIPJACK_CBC64,
	CKM_SKIPJACK_OFB64,
	CKM_SKIPJACK_CFB64,
	CKM_SKIPJACK_CFB32,
	CKM_SKIPJACK_CFB16,
	CKM_SKIPJACK_CFB8,
	CKM_SKIPJACK_WRAP,
	CKM_SKIPJACK_PRIVATE_WRAP,
	CKM_SKIPJACK_RELAYX,
	CKM_KEA_KEY_PAIR_GEN,
	CKM_KEA_KEY_DERIVE,
	CKM_KEA_DERIVE,
	CKM_FORTEZZA_TIMESTAMP,
	CKM_BATON_KEY_GEN,
	CKM_BATON_ECB128,
	CKM_BATON_ECB96,
	CKM_BATON_CBC128,
	CKM_BATON_COUNTER,
	CKM_BATON_SHUFFLE,
	CKM_BATON_WRAP,
	CKM_ECDSA_KEY_PAIR_GEN,
	CKM_EC_KEY_PAIR_GEN,
	CKM_ECDSA,
	CKM_ECDSA_SHA1,
	CKM_ECDSA_SHA224,
	CKM_ECDSA_SHA256,
	CKM_ECDSA_SHA384,
	CKM_ECDSA_SHA512,
	CKM_ECDH1_DERIVE,
	CKM_ECDH1_COFACTOR_DERIVE,
	CKM_ECMQV_DERIVE,
	CKM_ECDH_AES_KEY_WRAP,
	CKM_RSA_AES_KEY_WRAP,
	CKM_JUNIPER_KEY_GEN,
	CKM_JUNIPER_ECB128,
	CKM_JUNIPER_CBC128,
	CKM_JUNIPER_COUNTER,
	CKM_JUNIPER_SHUFFLE,
	CKM_JUNIPER_WRAP,
	CKM_FASTHASH,
	CKM_AES_KEY_GEN,
	CKM_AES_ECB,
	CKM_AES_CBC,
	CKM_AES_MAC,
	CKM_AES_MAC_GENERAL,
	CKM_AES_CBC_PAD,
	CKM_AES_CTR,
	CKM_AES_GCM,
	CKM_AES_CCM,
	CKM_AES_CTS,
	CKM_AES_CMAC,
	CKM_AES_CMAC_GENERAL,
	CKM_AES_XCBC_MAC,
	CKM_AES_XCBC_MAC_96,
	CKM_AES_GMAC,
	CKM_BLOWFISH_KEY_GEN,
	CKM_BLOWFISH_CBC,
	CKM_TWOFISH_KEY_GEN,
	CKM_TWOFISH_CBC,
	CKM_BLOWFISH_CBC_PAD,
	CKM_TWOFISH_CBC_PAD,
	CKM_DES_ECB_ENCRYPT_DATA,
	CKM_DES_CBC_ENCRYPT_DATA,
	CKM_DES3_ECB_ENCRYPT_DATA,
	CKM_DES3_CBC_ENCRYPT_DATA,
	CKM_AES_ECB_ENCRYPT_DATA,
	CKM_AES_CBC_ENCRYPT_DATA,
	CKM_GOSTR3410_KEY_PAIR_GEN,
	CKM_GOSTR3410,
	CKM_GOSTR3410_WITH_GOSTR3411,
	CKM_GOSTR3410_KEY_WRAP,
	CKM_GOSTR3410_DERIVE,
	CKM_GOSTR3411,
	CKM_GOSTR3411_HMAC,
	CKM_GOST28147_KEY_GEN,
	CKM_GOST28147_ECB,
	CKM_GOST28147,
	CKM_GOST28147_MAC,
	CKM_GOST28147_KEY_WRAP,
	CKM_DSA_PARAMETER_GEN,
	CKM_DH_PKCS_PARAMETER_GEN,
	CKM_X9_42_DH_PARAMETER_GEN,
	CKM_DSA_PROBABLISTIC_PARAMETER_GEN,
	CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
	CKM_AES_OFB,
	CKM_AES_CFB64,
	CKM_AES_CFB8,
	CKM_AES_CFB128,
	CKM_AES_CFB1,
	CKM_AES_KEY_WRAP,
	CKM_AES_KEY_WRAP_PAD,
	CKM_RSA_PKCS_TPM_1_1,
	CKM_RSA_PKCS_OAEP_TPM_1_1,
	CKM_VENDOR_DEFINED,
}