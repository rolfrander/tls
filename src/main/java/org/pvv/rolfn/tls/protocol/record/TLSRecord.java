package org.pvv.rolfn.tls.protocol.record;

public class TLSRecord {
	protected ContentType contentType;
	protected ProtocolVersion version;
	protected byte[] data;
	
	public ContentType getContentType() {
		return contentType;
	}
	
	public ProtocolVersion getVersion() {
		return version;
	}
	
	public int getLength() {
		return data.length;
	}
	
	public byte[] getData() {
		return data;
	}	
}