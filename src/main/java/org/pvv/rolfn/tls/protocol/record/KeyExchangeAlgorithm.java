package org.pvv.rolfn.tls.protocol.record;

public enum KeyExchangeAlgorithm {
	Null,
	dhe_dss, 
	dhe_rsa, 
	dh_anon, 
	rsa, 
	dh_dss, 
	dh_rsa, 
	ecdh_ecdsa, 
	ecdh_rsa, 
	ecdhe_ecdsa, 
	ecdhe_rsa, 
	ecdh_anon, 
	krb5, 
	psk,
	rsa_psk,
	dhe_psk,
	ecdhe_psk, 
	srp_sha, 
	srp_sha_rsa, 
	srp_sha_dss, 
	psk_dhe;
}
