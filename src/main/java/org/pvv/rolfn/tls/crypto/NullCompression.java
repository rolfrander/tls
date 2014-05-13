package org.pvv.rolfn.tls.crypto;

import org.pvv.rolfn.tls.protocol.record.Compression;
import org.pvv.rolfn.tls.protocol.record.TLSCompressed;
import org.pvv.rolfn.tls.protocol.record.TLSPlaintext;

public class NullCompression implements Compression {

	public static final NullCompression NULL = new NullCompression();
	
	private NullCompression() {
		
	}
	
	@Override
	public TLSCompressed compress(TLSPlaintext data) {
		TLSCompressed ret = new TLSCompressed(data.getContentType());
		ret.setData(data.getData());
		return ret;
	}

	@Override
	public TLSPlaintext decompress(TLSCompressed data) {
		TLSPlaintext ret = new TLSPlaintext(data.getContentType());
		ret.setData(data.getData());
		return ret;
	}

}
