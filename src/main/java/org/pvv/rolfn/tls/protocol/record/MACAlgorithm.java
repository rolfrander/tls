package org.pvv.rolfn.tls.protocol.record;

public enum MACAlgorithm {
	Null(0,0),
	md5(16,16), 
	sha1(20,20), 
	sha256(32,32), 
	sha384(48,48), 
	sha512(64,64);
	
	private int length;
	private int keyLength;

	private MACAlgorithm(int length, int keyLength) {
		this.length = length;
		this.keyLength = keyLength;
	}

	public int getLength() {
		return length;
	}

	public int getKeyLength() {
		return keyLength;
	}
}
