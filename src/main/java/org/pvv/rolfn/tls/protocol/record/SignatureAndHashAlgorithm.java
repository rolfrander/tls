package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class SignatureAndHashAlgorithm {
	private HashAlgorithm hashAlgorithm;
	private SignatureAlgorithm signatureAlgorithm;
	
	protected SignatureAndHashAlgorithm(ByteBuffer buf) {
		this.hashAlgorithm = HashAlgorithm.read(buf);
		this.signatureAlgorithm = SignatureAlgorithm.read(buf);
	}
}
