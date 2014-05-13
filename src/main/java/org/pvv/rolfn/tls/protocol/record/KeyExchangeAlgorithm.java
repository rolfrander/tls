package org.pvv.rolfn.tls.protocol.record;

public enum KeyExchangeAlgorithm {
	//           cert   ske
	Null        (false, false),
	dhe_dss     (true,  true), 
	dhe_rsa     (true,  true), 
	dh_anon     (false, true), 
	rsa         (true,  false), 
	dh_dss      (true,  false), 
	dh_rsa      (true,  false), 
	ecdh_ecdsa  (true,  false), 
	ecdh_rsa    (true,  false), 
	ecdhe_ecdsa (true,  true), 
	ecdhe_rsa   (true,  true), 
	ecdh_anon   (false, true), 
	krb5        (false, false), //? 
	psk         (false, false), //?
	rsa_psk     (true,  false), //?
	dhe_psk     (false, true),  //?
	ecdhe_psk   (false, true),  //? 
	srp_sha     (false, false), //?
	srp_sha_rsa (true,  false), //?
	srp_sha_dss (true,  false); //?
	
	private boolean needCert;
	private boolean needServerKeyExchange;

	private KeyExchangeAlgorithm(boolean needCert, boolean needServerKeyExchange) {
		this.needCert = needCert;
		this.needServerKeyExchange = needServerKeyExchange;
	}

	public boolean needCert() {
		return needCert;
	}

	public boolean needServerKeyExchange() {
		return needServerKeyExchange;
	}
	
	
}
