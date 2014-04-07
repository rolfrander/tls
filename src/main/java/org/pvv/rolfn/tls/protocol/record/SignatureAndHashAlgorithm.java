package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class SignatureAndHashAlgorithm {
	private HashAlgorithm hashAlgorithm;
	private SignatureAlgorithm signatureAlgorithm;
	
	public SignatureAndHashAlgorithm(HashAlgorithm h, SignatureAlgorithm s) {
		hashAlgorithm = h;
		signatureAlgorithm = s;
	}
	
	static protected SignatureAndHashAlgorithm read(ByteBuffer buf) {
		HashAlgorithm hash = HashAlgorithm.read(buf);
		SignatureAlgorithm signature = SignatureAlgorithm.read(buf);
		return new SignatureAndHashAlgorithm(hash, signature);
	}
	
	@Override
	public String toString() {
		return signatureAlgorithm.toString()+"-"+hashAlgorithm.toString();
	}

	public HashAlgorithm getHashAlgorithm() {
		return hashAlgorithm;
	}

	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
	}
	
	
}
