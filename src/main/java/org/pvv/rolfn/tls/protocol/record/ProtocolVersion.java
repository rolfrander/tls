package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

public class ProtocolVersion {
	private byte major;
	private byte minor;
	
	protected ProtocolVersion(ByteBuffer buf) {
		major = buf.get();
		minor = buf.get();
	}
	
	public byte getMajor() {
		return major;
	}
	
	public byte getMinor() {
		return minor;
	}
	
	public int getVersion() {
		int version = major;
		version = version << 8 + minor;
		return version;
	}
	
	public String toString() {
		switch(getVersion()) {
		case 0x0200: return "SSL 2.0";
		case 0x0300: return "SSL 3.0";
		case 0x0301: return "TLS 1.0";
		case 0x0302: return "TLS 1.1";
		case 0x0303: return "TLS 1.2";
		default: return "(unknown)";
		}
	}
}
