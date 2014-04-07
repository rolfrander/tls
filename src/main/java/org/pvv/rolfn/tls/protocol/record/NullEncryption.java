package org.pvv.rolfn.tls.protocol.record;

public class NullEncryption implements Encryption {

	public static final NullEncryption NULL = new NullEncryption();
	
	private NullEncryption() {
		
	}
	
	@Override
	public TLSCiphertext encrypt(TLSCompressed data) {
		TLSCiphertext ret = new TLSCiphertext();
		ret.contentType = data.contentType;
		ret.version = data.version;
		ret.data = data.data;
		return ret;
	}

	@Override
	public TLSCompressed decrypt(TLSCiphertext data) {
		TLSCompressed ret = new TLSCompressed();
		ret.contentType = data.contentType;
		ret.version = data.version;
		ret.data = data.data;
		return ret;
	}

}
