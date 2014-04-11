package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class TLSPlaintext extends TLSRecord {

	public TLSPlaintext(ContentType type, ByteBuffer data) {
		this.contentType = type;
		this.data = data;
	}
}
