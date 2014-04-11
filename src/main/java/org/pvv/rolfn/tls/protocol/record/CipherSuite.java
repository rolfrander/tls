package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.util.*;

import org.apache.log4j.Logger;
import org.pvv.rolfn.io.ByteBufferUtils;

public enum CipherSuite {
	TLS_NULL_WITH_NULL_NULL(0x0000,KeyExchangeAlgorithm.Null,Cipher.Null,MACAlgorithm.Null),
	TLS_RSA_WITH_NULL_MD5(0x0001,KeyExchangeAlgorithm.rsa,Cipher.Null,MACAlgorithm.md5),
	TLS_RSA_WITH_NULL_SHA(0x0002,KeyExchangeAlgorithm.rsa,Cipher.Null,MACAlgorithm.sha1),
	TLS_RSA_EXPORT_WITH_RC4_40_MD5(0x0003,KeyExchangeAlgorithm.rsa,Cipher.rc4_40,MACAlgorithm.md5),
	TLS_RSA_WITH_RC4_128_MD5(0x0004,KeyExchangeAlgorithm.rsa,Cipher.rc4_128,MACAlgorithm.md5),
	TLS_RSA_WITH_RC4_128_SHA(0x0005,KeyExchangeAlgorithm.rsa,Cipher.rc4_128,MACAlgorithm.sha1),
	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5(0x0006,KeyExchangeAlgorithm.rsa,Cipher.rc2_cbc_40,MACAlgorithm.md5),
	TLS_RSA_WITH_IDEA_CBC_SHA(0x0007,KeyExchangeAlgorithm.rsa,Cipher.idea_cbc,MACAlgorithm.sha1),
	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA(0x0008,KeyExchangeAlgorithm.rsa,Cipher.des40_cbc,MACAlgorithm.sha1),
	TLS_RSA_WITH_DES_CBC_SHA(0x0009,KeyExchangeAlgorithm.rsa,Cipher.des_cbc,MACAlgorithm.sha1),
	TLS_RSA_WITH_3DES_EDE_CBC_SHA(0x000A,KeyExchangeAlgorithm.rsa,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA(0x000B,KeyExchangeAlgorithm.dh_dss,Cipher.des40_cbc,MACAlgorithm.sha1),
	TLS_DH_DSS_WITH_DES_CBC_SHA(0x000C,KeyExchangeAlgorithm.dh_dss,Cipher.des_cbc,MACAlgorithm.sha1),
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA(0x000D,KeyExchangeAlgorithm.dh_dss,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA(0x000E,KeyExchangeAlgorithm.dh_rsa,Cipher.des40_cbc,MACAlgorithm.sha1),
	TLS_DH_RSA_WITH_DES_CBC_SHA(0x000F,KeyExchangeAlgorithm.dh_rsa,Cipher.des_cbc,MACAlgorithm.sha1),
	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA(0x0010,KeyExchangeAlgorithm.dh_rsa,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA(0x0011,KeyExchangeAlgorithm.dhe_dss,Cipher.des40_cbc,MACAlgorithm.sha1),
	TLS_DHE_DSS_WITH_DES_CBC_SHA(0x0012,KeyExchangeAlgorithm.dhe_dss,Cipher.des_cbc,MACAlgorithm.sha1),
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA(0x0013,KeyExchangeAlgorithm.dhe_dss,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA(0x0014,KeyExchangeAlgorithm.dhe_rsa,Cipher.des40_cbc,MACAlgorithm.sha1),
	TLS_DHE_RSA_WITH_DES_CBC_SHA(0x0015,KeyExchangeAlgorithm.dhe_rsa,Cipher.des_cbc,MACAlgorithm.sha1),
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(0x0016,KeyExchangeAlgorithm.dhe_rsa,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5(0x0017,KeyExchangeAlgorithm.dh_anon,Cipher.rc4_40,MACAlgorithm.md5),
	TLS_DH_anon_WITH_RC4_128_MD5(0x0018,KeyExchangeAlgorithm.dh_anon,Cipher.rc4_128,MACAlgorithm.md5),
	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA(0x0019,KeyExchangeAlgorithm.dh_anon,Cipher.des40_cbc,MACAlgorithm.sha1),
	TLS_DH_anon_WITH_DES_CBC_SHA(0x001A,KeyExchangeAlgorithm.dh_anon,Cipher.des_cbc,MACAlgorithm.sha1),
	TLS_DH_anon_WITH_3DES_EDE_CBC_SHA(0x001B,KeyExchangeAlgorithm.dh_anon,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_KRB5_WITH_DES_CBC_SHA(0x001E,KeyExchangeAlgorithm.krb5,Cipher.des_cbc,MACAlgorithm.sha1),
	TLS_KRB5_WITH_3DES_EDE_CBC_SHA(0x001F,KeyExchangeAlgorithm.krb5,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_KRB5_WITH_RC4_128_SHA(0x0020,KeyExchangeAlgorithm.krb5,Cipher.rc4_128,MACAlgorithm.sha1),
	TLS_KRB5_WITH_IDEA_CBC_SHA(0x0021,KeyExchangeAlgorithm.krb5,Cipher.idea_cbc,MACAlgorithm.sha1),
	TLS_KRB5_WITH_DES_CBC_MD5(0x0022,KeyExchangeAlgorithm.krb5,Cipher.des_cbc,MACAlgorithm.md5),
	TLS_KRB5_WITH_3DES_EDE_CBC_MD5(0x0023,KeyExchangeAlgorithm.krb5,Cipher.threedes_ede_cbc,MACAlgorithm.md5),
	TLS_KRB5_WITH_RC4_128_MD5(0x0024,KeyExchangeAlgorithm.krb5,Cipher.rc4_128,MACAlgorithm.md5),
	TLS_KRB5_WITH_IDEA_CBC_MD5(0x0025,KeyExchangeAlgorithm.krb5,Cipher.idea_cbc,MACAlgorithm.md5),
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA(0x0026,KeyExchangeAlgorithm.krb5,Cipher.des_cbc_40,MACAlgorithm.sha1),
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA(0x0027,KeyExchangeAlgorithm.krb5,Cipher.rc2_cbc_40,MACAlgorithm.sha1),
	TLS_KRB5_EXPORT_WITH_RC4_40_SHA(0x0028,KeyExchangeAlgorithm.krb5,Cipher.rc4_40,MACAlgorithm.sha1),
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5(0x0029,KeyExchangeAlgorithm.krb5,Cipher.des_cbc_40,MACAlgorithm.md5),
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5(0x002A,KeyExchangeAlgorithm.krb5,Cipher.rc2_cbc_40,MACAlgorithm.md5),
	TLS_KRB5_EXPORT_WITH_RC4_40_MD5(0x002B,KeyExchangeAlgorithm.krb5,Cipher.rc4_40,MACAlgorithm.md5),
	TLS_PSK_WITH_NULL_SHA(0x002C,KeyExchangeAlgorithm.psk,Cipher.Null,MACAlgorithm.sha1),
	TLS_DHE_PSK_WITH_NULL_SHA(0x002D,KeyExchangeAlgorithm.dhe_psk,Cipher.Null,MACAlgorithm.sha1),
	TLS_RSA_PSK_WITH_NULL_SHA(0x002E,KeyExchangeAlgorithm.rsa_psk,Cipher.Null,MACAlgorithm.sha1),
	TLS_RSA_WITH_AES_128_CBC_SHA(0x002F,KeyExchangeAlgorithm.rsa,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_DH_DSS_WITH_AES_128_CBC_SHA(0x0030,KeyExchangeAlgorithm.dh_dss,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_DH_RSA_WITH_AES_128_CBC_SHA(0x0031,KeyExchangeAlgorithm.dh_rsa,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA(0x0032,KeyExchangeAlgorithm.dhe_dss,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x0033,KeyExchangeAlgorithm.dhe_rsa,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_DH_anon_WITH_AES_128_CBC_SHA(0x0034,KeyExchangeAlgorithm.dh_anon,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_RSA_WITH_AES_256_CBC_SHA(0x0035,KeyExchangeAlgorithm.rsa,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_DH_DSS_WITH_AES_256_CBC_SHA(0x0036,KeyExchangeAlgorithm.dh_dss,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_DH_RSA_WITH_AES_256_CBC_SHA(0x0037,KeyExchangeAlgorithm.dh_rsa,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA(0x0038,KeyExchangeAlgorithm.dhe_dss,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x0039,KeyExchangeAlgorithm.dhe_rsa,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_DH_anon_WITH_AES_256_CBC_SHA(0x003A,KeyExchangeAlgorithm.dh_anon,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_RSA_WITH_NULL_SHA256(0x003B,KeyExchangeAlgorithm.rsa,Cipher.Null,MACAlgorithm.sha256),
	TLS_RSA_WITH_AES_128_CBC_SHA256(0x003C,KeyExchangeAlgorithm.rsa,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_RSA_WITH_AES_256_CBC_SHA256(0x003D,KeyExchangeAlgorithm.rsa,Cipher.aes_256_cbc,MACAlgorithm.sha256),
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256(0x003E,KeyExchangeAlgorithm.dh_dss,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_DH_RSA_WITH_AES_128_CBC_SHA256(0x003F,KeyExchangeAlgorithm.dh_rsa,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256(0x0040,KeyExchangeAlgorithm.dhe_dss,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0041,KeyExchangeAlgorithm.rsa,Cipher.camellia_128_cbc,MACAlgorithm.sha1),
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA(0x0042,KeyExchangeAlgorithm.dh_dss,Cipher.camellia_128_cbc,MACAlgorithm.sha1),
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0043,KeyExchangeAlgorithm.dh_rsa,Cipher.camellia_128_cbc,MACAlgorithm.sha1),
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA(0x0044,KeyExchangeAlgorithm.dhe_dss,Cipher.camellia_128_cbc,MACAlgorithm.sha1),
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0045,KeyExchangeAlgorithm.dhe_rsa,Cipher.camellia_128_cbc,MACAlgorithm.sha1),
	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA(0x0046,KeyExchangeAlgorithm.dh_anon,Cipher.camellia_128_cbc,MACAlgorithm.sha1),
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x0067,KeyExchangeAlgorithm.dhe_rsa,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_DH_DSS_WITH_AES_256_CBC_SHA256(0x0068,KeyExchangeAlgorithm.dh_dss,Cipher.aes_256_cbc,MACAlgorithm.sha256),
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256(0x0069,KeyExchangeAlgorithm.dh_rsa,Cipher.aes_256_cbc,MACAlgorithm.sha256),
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256(0x006A,KeyExchangeAlgorithm.dhe_dss,Cipher.aes_256_cbc,MACAlgorithm.sha256),
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x006B,KeyExchangeAlgorithm.dhe_rsa,Cipher.aes_256_cbc,MACAlgorithm.sha256),
	TLS_DH_anon_WITH_AES_128_CBC_SHA256(0x006C,KeyExchangeAlgorithm.dh_anon,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_DH_anon_WITH_AES_256_CBC_SHA256(0x006D,KeyExchangeAlgorithm.dh_anon,Cipher.aes_256_cbc,MACAlgorithm.sha256),
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0084,KeyExchangeAlgorithm.rsa,Cipher.camellia_256_cbc,MACAlgorithm.sha1),
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA(0x0085,KeyExchangeAlgorithm.dh_dss,Cipher.camellia_256_cbc,MACAlgorithm.sha1),
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0086,KeyExchangeAlgorithm.dh_rsa,Cipher.camellia_256_cbc,MACAlgorithm.sha1),
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA(0x0087,KeyExchangeAlgorithm.dhe_dss,Cipher.camellia_256_cbc,MACAlgorithm.sha1),
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0088,KeyExchangeAlgorithm.dhe_rsa,Cipher.camellia_256_cbc,MACAlgorithm.sha1),
	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA(0x0089,KeyExchangeAlgorithm.dh_anon,Cipher.camellia_256_cbc,MACAlgorithm.sha1),
	TLS_PSK_WITH_RC4_128_SHA(0x008A,KeyExchangeAlgorithm.psk,Cipher.rc4_128,MACAlgorithm.sha1),
	TLS_PSK_WITH_3DES_EDE_CBC_SHA(0x008B,KeyExchangeAlgorithm.psk,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_PSK_WITH_AES_128_CBC_SHA(0x008C,KeyExchangeAlgorithm.psk,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_PSK_WITH_AES_256_CBC_SHA(0x008D,KeyExchangeAlgorithm.psk,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_DHE_PSK_WITH_RC4_128_SHA(0x008E,KeyExchangeAlgorithm.dhe_psk,Cipher.rc4_128,MACAlgorithm.sha1),
	TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA(0x008F,KeyExchangeAlgorithm.dhe_psk,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA(0x0090,KeyExchangeAlgorithm.dhe_psk,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA(0x0091,KeyExchangeAlgorithm.dhe_psk,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_RSA_PSK_WITH_RC4_128_SHA(0x0092,KeyExchangeAlgorithm.rsa_psk,Cipher.rc4_128,MACAlgorithm.sha1),
	TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA(0x0093,KeyExchangeAlgorithm.rsa_psk,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA(0x0094,KeyExchangeAlgorithm.rsa_psk,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA(0x0095,KeyExchangeAlgorithm.rsa_psk,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_RSA_WITH_SEED_CBC_SHA(0x0096,KeyExchangeAlgorithm.rsa,Cipher.seed_cbc,MACAlgorithm.sha1),
	TLS_DH_DSS_WITH_SEED_CBC_SHA(0x0097,KeyExchangeAlgorithm.dh_dss,Cipher.seed_cbc,MACAlgorithm.sha1),
	TLS_DH_RSA_WITH_SEED_CBC_SHA(0x0098,KeyExchangeAlgorithm.dh_rsa,Cipher.seed_cbc,MACAlgorithm.sha1),
	TLS_DHE_DSS_WITH_SEED_CBC_SHA(0x0099,KeyExchangeAlgorithm.dhe_dss,Cipher.seed_cbc,MACAlgorithm.sha1),
	TLS_DHE_RSA_WITH_SEED_CBC_SHA(0x009A,KeyExchangeAlgorithm.dhe_rsa,Cipher.seed_cbc,MACAlgorithm.sha1),
	TLS_DH_anon_WITH_SEED_CBC_SHA(0x009B,KeyExchangeAlgorithm.dh_anon,Cipher.seed_cbc,MACAlgorithm.sha1),
	TLS_RSA_WITH_AES_128_GCM_SHA256(0x009C,KeyExchangeAlgorithm.rsa,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_RSA_WITH_AES_256_GCM_SHA384(0x009D,KeyExchangeAlgorithm.rsa,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x009E,KeyExchangeAlgorithm.dhe_rsa,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(0x009F,KeyExchangeAlgorithm.dhe_rsa,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_DH_RSA_WITH_AES_128_GCM_SHA256(0x00A0,KeyExchangeAlgorithm.dh_rsa,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_DH_RSA_WITH_AES_256_GCM_SHA384(0x00A1,KeyExchangeAlgorithm.dh_rsa,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_DHE_DSS_WITH_AES_128_GCM_SHA256(0x00A2,KeyExchangeAlgorithm.dhe_dss,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_DHE_DSS_WITH_AES_256_GCM_SHA384(0x00A3,KeyExchangeAlgorithm.dhe_dss,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_DH_DSS_WITH_AES_128_GCM_SHA256(0x00A4,KeyExchangeAlgorithm.dh_dss,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_DH_DSS_WITH_AES_256_GCM_SHA384(0x00A5,KeyExchangeAlgorithm.dh_dss,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_DH_anon_WITH_AES_128_GCM_SHA256(0x00A6,KeyExchangeAlgorithm.dh_anon,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_DH_anon_WITH_AES_256_GCM_SHA384(0x00A7,KeyExchangeAlgorithm.dh_anon,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_PSK_WITH_AES_128_GCM_SHA256(0x00A8,KeyExchangeAlgorithm.psk,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_PSK_WITH_AES_256_GCM_SHA384(0x00A9,KeyExchangeAlgorithm.psk,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256(0x00AA,KeyExchangeAlgorithm.dhe_psk,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_DHE_PSK_WITH_AES_256_GCM_SHA384(0x00AB,KeyExchangeAlgorithm.dhe_psk,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_RSA_PSK_WITH_AES_128_GCM_SHA256(0x00AC,KeyExchangeAlgorithm.rsa_psk,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_RSA_PSK_WITH_AES_256_GCM_SHA384(0x00AD,KeyExchangeAlgorithm.rsa_psk,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_PSK_WITH_AES_128_CBC_SHA256(0x00AE,KeyExchangeAlgorithm.psk,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_PSK_WITH_AES_256_CBC_SHA384(0x00AF,KeyExchangeAlgorithm.psk,Cipher.aes_256_cbc,MACAlgorithm.sha384),
	TLS_PSK_WITH_NULL_SHA256(0x00B0,KeyExchangeAlgorithm.psk,Cipher.Null,MACAlgorithm.sha256),
	TLS_PSK_WITH_NULL_SHA384(0x00B1,KeyExchangeAlgorithm.psk,Cipher.Null,MACAlgorithm.sha384),
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256(0x00B2,KeyExchangeAlgorithm.dhe_psk,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA384(0x00B3,KeyExchangeAlgorithm.dhe_psk,Cipher.aes_256_cbc,MACAlgorithm.sha384),
	TLS_DHE_PSK_WITH_NULL_SHA256(0x00B4,KeyExchangeAlgorithm.dhe_psk,Cipher.Null,MACAlgorithm.sha256),
	TLS_DHE_PSK_WITH_NULL_SHA384(0x00B5,KeyExchangeAlgorithm.dhe_psk,Cipher.Null,MACAlgorithm.sha384),
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA256(0x00B6,KeyExchangeAlgorithm.rsa_psk,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA384(0x00B7,KeyExchangeAlgorithm.rsa_psk,Cipher.aes_256_cbc,MACAlgorithm.sha384),
	TLS_RSA_PSK_WITH_NULL_SHA256(0x00B8,KeyExchangeAlgorithm.rsa_psk,Cipher.Null,MACAlgorithm.sha256),
	TLS_RSA_PSK_WITH_NULL_SHA384(0x00B9,KeyExchangeAlgorithm.rsa_psk,Cipher.Null,MACAlgorithm.sha384),
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00BA,KeyExchangeAlgorithm.rsa,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256(0x00BB,KeyExchangeAlgorithm.dh_dss,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00BC,KeyExchangeAlgorithm.dh_rsa,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256(0x00BD,KeyExchangeAlgorithm.dhe_dss,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00BE,KeyExchangeAlgorithm.dhe_rsa,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256(0x00BF,KeyExchangeAlgorithm.dh_anon,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00C0,KeyExchangeAlgorithm.rsa,Cipher.camellia_256_cbc,MACAlgorithm.sha256),
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256(0x00C1,KeyExchangeAlgorithm.dh_dss,Cipher.camellia_256_cbc,MACAlgorithm.sha256),
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00C2,KeyExchangeAlgorithm.dh_rsa,Cipher.camellia_256_cbc,MACAlgorithm.sha256),
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256(0x00C3,KeyExchangeAlgorithm.dhe_dss,Cipher.camellia_256_cbc,MACAlgorithm.sha256),
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00C4,KeyExchangeAlgorithm.dhe_rsa,Cipher.camellia_256_cbc,MACAlgorithm.sha256),
	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256(0x00C5,KeyExchangeAlgorithm.dh_anon,Cipher.camellia_256_cbc,MACAlgorithm.sha256),
	TLS_ECDH_ECDSA_WITH_NULL_SHA(0xC001,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.Null,MACAlgorithm.sha1),
	TLS_ECDH_ECDSA_WITH_RC4_128_SHA(0xC002,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.rc4_128,MACAlgorithm.sha1),
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA(0xC003,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(0xC004,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA(0xC005,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_ECDHE_ECDSA_WITH_NULL_SHA(0xC006,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.Null,MACAlgorithm.sha1),
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA(0xC007,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.rc4_128,MACAlgorithm.sha1),
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA(0xC008,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xC009,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xC00A,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_ECDH_RSA_WITH_NULL_SHA(0xC00B,KeyExchangeAlgorithm.ecdh_rsa,Cipher.Null,MACAlgorithm.sha1),
	TLS_ECDH_RSA_WITH_RC4_128_SHA(0xC00C,KeyExchangeAlgorithm.ecdh_rsa,Cipher.rc4_128,MACAlgorithm.sha1),
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA(0xC00D,KeyExchangeAlgorithm.ecdh_rsa,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA(0xC00E,KeyExchangeAlgorithm.ecdh_rsa,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA(0xC00F,KeyExchangeAlgorithm.ecdh_rsa,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_ECDHE_RSA_WITH_NULL_SHA(0xC010,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.Null,MACAlgorithm.sha1),
	TLS_ECDHE_RSA_WITH_RC4_128_SHA(0xC011,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.rc4_128,MACAlgorithm.sha1),
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA(0xC012,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xC013,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xC014,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_ECDH_anon_WITH_NULL_SHA(0xC015,KeyExchangeAlgorithm.ecdh_anon,Cipher.Null,MACAlgorithm.sha1),
	TLS_ECDH_anon_WITH_RC4_128_SHA(0xC016,KeyExchangeAlgorithm.ecdh_anon,Cipher.rc4_128,MACAlgorithm.sha1),
	TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA(0xC017,KeyExchangeAlgorithm.ecdh_anon,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_ECDH_anon_WITH_AES_128_CBC_SHA(0xC018,KeyExchangeAlgorithm.ecdh_anon,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_ECDH_anon_WITH_AES_256_CBC_SHA(0xC019,KeyExchangeAlgorithm.ecdh_anon,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA(0xC01A,KeyExchangeAlgorithm.srp_sha,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA(0xC01B,KeyExchangeAlgorithm.srp_sha_rsa,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA(0xC01C,KeyExchangeAlgorithm.srp_sha_dss,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_SRP_SHA_WITH_AES_128_CBC_SHA(0xC01D,KeyExchangeAlgorithm.srp_sha,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA(0xC01E,KeyExchangeAlgorithm.srp_sha_rsa,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA(0xC01F,KeyExchangeAlgorithm.srp_sha_dss,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_SRP_SHA_WITH_AES_256_CBC_SHA(0xC020,KeyExchangeAlgorithm.srp_sha,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA(0xC021,KeyExchangeAlgorithm.srp_sha_rsa,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA(0xC022,KeyExchangeAlgorithm.srp_sha_dss,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xC023,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(0xC024,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.aes_256_cbc,MACAlgorithm.sha384),
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256(0xC025,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384(0xC026,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.aes_256_cbc,MACAlgorithm.sha384),
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xC027,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(0xC028,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.aes_256_cbc,MACAlgorithm.sha384),
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256(0xC029,KeyExchangeAlgorithm.ecdh_rsa,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384(0xC02A,KeyExchangeAlgorithm.ecdh_rsa,Cipher.aes_256_cbc,MACAlgorithm.sha384),
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xC02B,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xC02C,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256(0xC02D,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384(0xC02E,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xC02F,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xC030,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256(0xC031,KeyExchangeAlgorithm.ecdh_rsa,Cipher.aes_128_gcm,MACAlgorithm.sha256),
	TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384(0xC032,KeyExchangeAlgorithm.ecdh_rsa,Cipher.aes_256_gcm,MACAlgorithm.sha384),
	TLS_ECDHE_PSK_WITH_RC4_128_SHA(0xC033,KeyExchangeAlgorithm.ecdhe_psk,Cipher.rc4_128,MACAlgorithm.sha1),
	TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA(0xC034,KeyExchangeAlgorithm.ecdhe_psk,Cipher.threedes_ede_cbc,MACAlgorithm.sha1),
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA(0xC035,KeyExchangeAlgorithm.ecdhe_psk,Cipher.aes_128_cbc,MACAlgorithm.sha1),
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA(0xC036,KeyExchangeAlgorithm.ecdhe_psk,Cipher.aes_256_cbc,MACAlgorithm.sha1),
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256(0xC037,KeyExchangeAlgorithm.ecdhe_psk,Cipher.aes_128_cbc,MACAlgorithm.sha256),
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384(0xC038,KeyExchangeAlgorithm.ecdhe_psk,Cipher.aes_256_cbc,MACAlgorithm.sha384),
	TLS_ECDHE_PSK_WITH_NULL_SHA(0xC039,KeyExchangeAlgorithm.ecdhe_psk,Cipher.Null,MACAlgorithm.sha1),
	TLS_ECDHE_PSK_WITH_NULL_SHA256(0xC03A,KeyExchangeAlgorithm.ecdhe_psk,Cipher.Null,MACAlgorithm.sha256),
	TLS_ECDHE_PSK_WITH_NULL_SHA384(0xC03B,KeyExchangeAlgorithm.ecdhe_psk,Cipher.Null,MACAlgorithm.sha384),
	TLS_RSA_WITH_ARIA_128_CBC_SHA256(0xC03C,KeyExchangeAlgorithm.rsa,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_RSA_WITH_ARIA_256_CBC_SHA384(0xC03D,KeyExchangeAlgorithm.rsa,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256(0xC03E,KeyExchangeAlgorithm.dh_dss,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384(0xC03F,KeyExchangeAlgorithm.dh_dss,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256(0xC040,KeyExchangeAlgorithm.dh_rsa,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384(0xC041,KeyExchangeAlgorithm.dh_rsa,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256(0xC042,KeyExchangeAlgorithm.dhe_dss,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384(0xC043,KeyExchangeAlgorithm.dhe_dss,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256(0xC044,KeyExchangeAlgorithm.dhe_rsa,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384(0xC045,KeyExchangeAlgorithm.dhe_rsa,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_DH_anon_WITH_ARIA_128_CBC_SHA256(0xC046,KeyExchangeAlgorithm.dh_anon,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_DH_anon_WITH_ARIA_256_CBC_SHA384(0xC047,KeyExchangeAlgorithm.dh_anon,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256(0xC048,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384(0xC049,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256(0xC04A,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384(0xC04B,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256(0xC04C,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384(0xC04D,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256(0xC04E,KeyExchangeAlgorithm.ecdh_rsa,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384(0xC04F,KeyExchangeAlgorithm.ecdh_rsa,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_RSA_WITH_ARIA_128_GCM_SHA256(0xC050,KeyExchangeAlgorithm.rsa,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_RSA_WITH_ARIA_256_GCM_SHA384(0xC051,KeyExchangeAlgorithm.rsa,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256(0xC052,KeyExchangeAlgorithm.dhe_rsa,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384(0xC053,KeyExchangeAlgorithm.dhe_rsa,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256(0xC054,KeyExchangeAlgorithm.dh_rsa,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384(0xC055,KeyExchangeAlgorithm.dh_rsa,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256(0xC056,KeyExchangeAlgorithm.dhe_dss,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384(0xC057,KeyExchangeAlgorithm.dhe_dss,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256(0xC058,KeyExchangeAlgorithm.dh_dss,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384(0xC059,KeyExchangeAlgorithm.dh_dss,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_DH_anon_WITH_ARIA_128_GCM_SHA256(0xC05A,KeyExchangeAlgorithm.dh_anon,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_DH_anon_WITH_ARIA_256_GCM_SHA384(0xC05B,KeyExchangeAlgorithm.dh_anon,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256(0xC05C,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384(0xC05D,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256(0xC05E,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384(0xC05F,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256(0xC060,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384(0xC061,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256(0xC062,KeyExchangeAlgorithm.ecdh_rsa,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384(0xC063,KeyExchangeAlgorithm.ecdh_rsa,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_PSK_WITH_ARIA_128_CBC_SHA256(0xC064,KeyExchangeAlgorithm.psk,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_PSK_WITH_ARIA_256_CBC_SHA384(0xC065,KeyExchangeAlgorithm.psk,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256(0xC066,KeyExchangeAlgorithm.dhe_psk,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384(0xC067,KeyExchangeAlgorithm.dhe_psk,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256(0xC068,KeyExchangeAlgorithm.rsa_psk,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384(0xC069,KeyExchangeAlgorithm.rsa_psk,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_PSK_WITH_ARIA_128_GCM_SHA256(0xC06A,KeyExchangeAlgorithm.psk,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_PSK_WITH_ARIA_256_GCM_SHA384(0xC06B,KeyExchangeAlgorithm.psk,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256(0xC06C,KeyExchangeAlgorithm.dhe_psk,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384(0xC06D,KeyExchangeAlgorithm.dhe_psk,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256(0xC06E,KeyExchangeAlgorithm.rsa_psk,Cipher.aria_128_gcm,MACAlgorithm.sha256),
	TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384(0xC06F,KeyExchangeAlgorithm.rsa_psk,Cipher.aria_256_gcm,MACAlgorithm.sha384),
	TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256(0xC070,KeyExchangeAlgorithm.ecdhe_psk,Cipher.aria_128_cbc,MACAlgorithm.sha256),
	TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384(0xC071,KeyExchangeAlgorithm.ecdhe_psk,Cipher.aria_256_cbc,MACAlgorithm.sha384),
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(0xC072,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(0xC073,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.camellia_256_cbc,MACAlgorithm.sha384),
	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(0xC074,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(0xC075,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.camellia_256_cbc,MACAlgorithm.sha384),
	TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xC076,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384(0xC077,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.camellia_256_cbc,MACAlgorithm.sha384),
	TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xC078,KeyExchangeAlgorithm.ecdh_rsa,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384(0xC079,KeyExchangeAlgorithm.ecdh_rsa,Cipher.camellia_256_cbc,MACAlgorithm.sha384),
	TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07A,KeyExchangeAlgorithm.rsa,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07B,KeyExchangeAlgorithm.rsa,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07C,KeyExchangeAlgorithm.dhe_rsa,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07D,KeyExchangeAlgorithm.dhe_rsa,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07E,KeyExchangeAlgorithm.dh_rsa,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07F,KeyExchangeAlgorithm.dh_rsa,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256(0xC080,KeyExchangeAlgorithm.dhe_dss,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384(0xC081,KeyExchangeAlgorithm.dhe_dss,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256(0xC082,KeyExchangeAlgorithm.dh_dss,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384(0xC083,KeyExchangeAlgorithm.dh_dss,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256(0xC084,KeyExchangeAlgorithm.dh_anon,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384(0xC085,KeyExchangeAlgorithm.dh_anon,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(0xC086,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(0xC087,KeyExchangeAlgorithm.ecdhe_ecdsa,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(0xC088,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(0xC089,KeyExchangeAlgorithm.ecdh_ecdsa,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC08A,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC08B,KeyExchangeAlgorithm.ecdhe_rsa,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC08C,KeyExchangeAlgorithm.ecdh_rsa,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC08D,KeyExchangeAlgorithm.ecdh_rsa,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC08E,KeyExchangeAlgorithm.psk,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC08F,KeyExchangeAlgorithm.psk,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC090,KeyExchangeAlgorithm.dhe_psk,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC091,KeyExchangeAlgorithm.dhe_psk,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC092,KeyExchangeAlgorithm.rsa_psk,Cipher.camellia_128_gcm,MACAlgorithm.sha256),
	TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC093,KeyExchangeAlgorithm.rsa_psk,Cipher.camellia_256_gcm,MACAlgorithm.sha384),
	TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC094,KeyExchangeAlgorithm.psk,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC095,KeyExchangeAlgorithm.psk,Cipher.camellia_256_cbc,MACAlgorithm.sha384),
	TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC096,KeyExchangeAlgorithm.dhe_psk,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC097,KeyExchangeAlgorithm.dhe_psk,Cipher.camellia_256_cbc,MACAlgorithm.sha384),
	TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC098,KeyExchangeAlgorithm.rsa_psk,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC099,KeyExchangeAlgorithm.rsa_psk,Cipher.camellia_256_cbc,MACAlgorithm.sha384),
	TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC09A,KeyExchangeAlgorithm.ecdhe_psk,Cipher.camellia_128_cbc,MACAlgorithm.sha256),
	TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC09B,KeyExchangeAlgorithm.ecdhe_psk,Cipher.camellia_256_cbc,MACAlgorithm.sha384),
	TLS_RSA_WITH_AES_128_CCM(0xC09C,KeyExchangeAlgorithm.rsa,Cipher.aes_128_ccm,MACAlgorithm.sha256),
	TLS_RSA_WITH_AES_256_CCM(0xC09D,KeyExchangeAlgorithm.rsa,Cipher.aes_256_ccm,MACAlgorithm.sha256),
	TLS_DHE_RSA_WITH_AES_128_CCM(0xC09E,KeyExchangeAlgorithm.dhe_rsa,Cipher.aes_128_ccm,MACAlgorithm.sha256),
	TLS_DHE_RSA_WITH_AES_256_CCM(0xC09F,KeyExchangeAlgorithm.dhe_rsa,Cipher.aes_256_ccm,MACAlgorithm.sha256),
	TLS_RSA_WITH_AES_128_CCM_8(0xC0A0,KeyExchangeAlgorithm.rsa,Cipher.aes_128_ccm_8,MACAlgorithm.sha256),
	TLS_RSA_WITH_AES_256_CCM_8(0xC0A1,KeyExchangeAlgorithm.rsa,Cipher.aes_256_ccm_8,MACAlgorithm.sha256),
	TLS_DHE_RSA_WITH_AES_128_CCM_8(0xC0A2,KeyExchangeAlgorithm.dhe_rsa,Cipher.aes_128_ccm_8,MACAlgorithm.sha256),
	TLS_DHE_RSA_WITH_AES_256_CCM_8(0xC0A3,KeyExchangeAlgorithm.dhe_rsa,Cipher.aes_256_ccm_8,MACAlgorithm.sha256),
	TLS_PSK_WITH_AES_128_CCM(0xC0A4,KeyExchangeAlgorithm.psk,Cipher.aes_128_ccm,MACAlgorithm.sha256),
	TLS_PSK_WITH_AES_256_CCM(0xC0A5,KeyExchangeAlgorithm.psk,Cipher.aes_256_ccm,MACAlgorithm.sha256),
	TLS_DHE_PSK_WITH_AES_128_CCM(0xC0A6,KeyExchangeAlgorithm.dhe_psk,Cipher.aes_128_ccm,MACAlgorithm.sha256),
	TLS_DHE_PSK_WITH_AES_256_CCM(0xC0A7,KeyExchangeAlgorithm.dhe_psk,Cipher.aes_256_ccm,MACAlgorithm.sha256),
	TLS_PSK_WITH_AES_128_CCM_8(0xC0A8,KeyExchangeAlgorithm.psk,Cipher.aes_128_ccm_8,MACAlgorithm.sha256),
	TLS_PSK_WITH_AES_256_CCM_8(0xC0A9,KeyExchangeAlgorithm.psk,Cipher.aes_256_ccm_8,MACAlgorithm.sha256),
	TLS_PSK_DHE_WITH_AES_128_CCM_8(0xC0AA,KeyExchangeAlgorithm.psk_dhe,Cipher.aes_128_ccm_8,MACAlgorithm.sha256),
	TLS_PSK_DHE_WITH_AES_256_CCM_8(0xC0AB,KeyExchangeAlgorithm.psk_dhe,Cipher.aes_256_ccm_8,MACAlgorithm.sha256);
	
	static private final Logger log = Logger.getLogger(CipherSuite.class);
	private int cipherSuite;
	private KeyExchangeAlgorithm keyExchange;
	private Cipher cipher;
	private MACAlgorithm mac;
	private int verifyDataLength = 0;
	private static Map<Integer,CipherSuite> suites;
	
	private CipherSuite(int id, KeyExchangeAlgorithm kx, Cipher cipher, MACAlgorithm mac) {
		cipherSuite = id;
		keyExchange = kx;
		this.cipher = cipher;
		this.mac = mac;
	}

	private CipherSuite(int id, KeyExchangeAlgorithm kx, Cipher cipher, MACAlgorithm mac, int verifyDataLength) {
		this(id, kx, cipher, mac);
		this.verifyDataLength = verifyDataLength;
	}
	
	synchronized private static Map<Integer,CipherSuite> getSuites() {
		if(suites == null) {
			suites = new TreeMap<Integer,CipherSuite>();
			for(CipherSuite c: CipherSuite.values()) {
				suites.put(c.cipherSuite, c);
			}
		}
		return suites;
	}
	
	public static CipherSuite fromId(int id) {
		if(suites == null) {
			getSuites();
		}
		if(!suites.containsKey(id)) {
			log.error(String.format("Unknown cipher suite: %04x", id));
			return null;
		} else {
			return suites.get(id);
		}
	}
	
	protected static CipherSuite read(ByteBuffer buf) {
		return fromId(ByteBufferUtils.getUnsignedShort(buf));
	}

	public void write(ByteBuffer buf) {
		buf.putShort((short) cipherSuite);
	}
	
	static protected final int octets() {
		return 2;
	}
	
	public int getId() {
		return cipherSuite;
	}
	
	public int getCipherSuite() {
		return cipherSuite;
	}

	public Cipher getCipher() {
		return cipher;
	}

	public MACAlgorithm getMac() {
		return mac;
	}

	public int getVerifyDataLength() {
		return verifyDataLength;
	}

	public KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
		return keyExchange;
	}
	
	public String toString() {
		return String.format("0x%04x %s", cipherSuite, this.name());
	}

}
