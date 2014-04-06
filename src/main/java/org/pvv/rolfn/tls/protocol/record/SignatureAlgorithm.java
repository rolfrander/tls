package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public enum SignatureAlgorithm {
	anonymous(0), rsa(1), dsa(2), ecdsa(3);
	
	private int id;

	private SignatureAlgorithm(int id) {
		this.id = id;
	}
	
	protected static SignatureAlgorithm read(ByteBuffer buf) {
		return fromId(ByteBufferUtils.getUnsignedByte(buf));
	}
	
	public static SignatureAlgorithm fromId(int id) {
		switch(id) {
		case 0: return anonymous;
		case 1: return rsa;
		case 2: return dsa;
		case 3: return ecdsa;
		}
		return null;
	}	
}
