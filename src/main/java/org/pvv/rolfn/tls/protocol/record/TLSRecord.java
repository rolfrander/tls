package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class TLSRecord {
	private ContentType contentType;
	private ByteBuffer data;
	
	public TLSRecord(ContentType contentType) {
		this.contentType = contentType;
	}
	
	public ContentType getContentType() {
		return contentType;
	}
	
	public int getLength() {
		return data.remaining();
	}
	
	public ByteBuffer getData() {
		return data;
	}	
	
	/**
	 * set payload.
	 * @param data payload
	 * @return this
	 */
	public TLSRecord setData(ByteBuffer data) {
		this.data = data;
		return this;
	}
}