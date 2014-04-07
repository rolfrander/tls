package org.pvv.rolfn.tls.protocol.record;

public class TLSPlaintext extends TLSRecord {

	public TLSPlaintext(ContentType type, byte[] data) {
		this.contentType = type;
		this.data = data;
	}
}
