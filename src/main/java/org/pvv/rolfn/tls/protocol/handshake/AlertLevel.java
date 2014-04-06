package org.pvv.rolfn.tls.protocol.handshake;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public enum AlertLevel {
	warning(1), fatal(2);
	
	private int id;

	private AlertLevel(int id) {
		this.id = id;
	}
	
	protected static AlertLevel read(ByteBuffer buf) {
		return fromId(ByteBufferUtils.getUnsignedByte(buf));
	}
	
	public static AlertLevel fromId(int id) {
		switch(id) {
		case 1: return warning;
		case 2: return fatal;

		default: return null;
		}
	}
}
