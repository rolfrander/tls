package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

public enum ProtocolVersion {
	SSL2_0(2,0),
	SSL3_0(3,0),
	TLS1_0(3,1),
	TLS1_1(3,2),
	TLS1_2(3,3);
	
	private byte major;
	private byte minor;

	
	private ProtocolVersion(int major, int minor) {
		this.major = (byte) (0xff & major);
		this.minor = (byte) (0xff & minor);
	}
	
	static protected ProtocolVersion read(ByteBuffer buf) {
		byte maj = buf.get();
		byte min = buf.get();
		if(maj == 2 && min == 0) {
			return SSL2_0;
		}
		if(maj == 3) {
			switch(min) {
			case 0:
				return SSL3_0;
			case 1:
				return TLS1_0;
			case 2:
				return TLS1_1;
			case 3:
				return TLS1_2;
			}
		}
		return null;
	}
	
	public byte getMajor() {
		return major;
	}
	
	public byte getMinor() {
		return minor;
	}
	
	public int getVersion() {
		int version = major;
		version = version << 8 | minor;
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

	public void write(ByteBuffer buf) {
		buf.put(major);
		buf.put(minor);
	}
}
