package org.pvv.rolfn.tls.protocol.record;

public class NullCompression implements Compression {

	public static final NullCompression NULL = new NullCompression();
	
	private NullCompression() {
		
	}
	
	@Override
	public TLSCompressed compress(TLSPlaintext data) {
		TLSCompressed ret = new TLSCompressed();
		ret.contentType = data.contentType;
		ret.version = data.version;
		ret.data = data.data;
		return ret;
	}

	@Override
	public TLSPlaintext decompress(TLSCompressed data) {
		TLSPlaintext ret = new TLSPlaintext(data.contentType, data.data);
		ret.version = data.version;
		return ret;
	}

}
