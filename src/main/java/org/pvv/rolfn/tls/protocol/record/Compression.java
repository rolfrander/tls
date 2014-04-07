package org.pvv.rolfn.tls.protocol.record;

public interface Compression {
	TLSCompressed compress(TLSPlaintext in);
	TLSPlaintext decompress(TLSCompressed in);
}
