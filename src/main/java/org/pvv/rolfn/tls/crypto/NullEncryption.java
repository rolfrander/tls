package org.pvv.rolfn.tls.crypto;

import org.pvv.rolfn.tls.protocol.record.Encryption;
import org.pvv.rolfn.tls.protocol.record.TLSCiphertext;
import org.pvv.rolfn.tls.protocol.record.TLSCompressed;

public class NullEncryption implements Encryption {

	public static final NullEncryption NULL = new NullEncryption();
	
	private NullEncryption() {
		
	}
	
	@Override
	public TLSCiphertext encrypt(TLSCompressed data) {
		TLSCiphertext ret = new TLSCiphertext(data.getContentType());
		ret.setData(data.getData());
		return ret;
	}

	@Override
	public TLSCompressed decrypt(TLSCiphertext data) {
		TLSCompressed ret = new TLSCompressed(data.getContentType());
		ret.setData(data.getData());
		return ret;
	}

}
