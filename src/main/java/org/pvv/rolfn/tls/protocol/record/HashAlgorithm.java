package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public enum HashAlgorithm {
	none(0), 
	md5(1), 
	sha1(2), 
	sha224(3), 
	sha256(4), 
	sha384(5),
    sha512(6);
	
	private int id;

	private HashAlgorithm(int id) {
		this.id = id;
	}
	
	public static HashAlgorithm read(ByteBuffer buf) {
		return fromId(RecordUtils.getUnsignedByte(buf));
	}
	
	public static HashAlgorithm fromId(int id) {
		switch(id) {
		case 0: return none;
		case 1: return md5;
		case 2: return sha1;
		case 3: return sha224;
		case 4: return sha256;
		case 5: return sha384;
		case 6: return sha512;
		}
		return null;
	}
}
