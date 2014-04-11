package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class TLSRecord {
	protected ContentType contentType;
	protected ProtocolVersion version;
	protected ByteBuffer data;
	
	public ContentType getContentType() {
		return contentType;
	}
	
	public ProtocolVersion getVersion() {
		return version;
	}
	
	public int getLength() {
		return data.limit();
	}
	
	public ByteBuffer getData() {
		return data;
	}	
}