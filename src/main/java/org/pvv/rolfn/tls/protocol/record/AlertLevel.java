package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public enum AlertLevel {
	warning(1), fatal(2);
	
	private int id;

	private AlertLevel(int id) {
		this.id = id;
	}
	
	public static AlertLevel read(ByteBuffer buf) {
		return fromId(RecordUtils.getUnsignedByte(buf));
	}
	
	public static AlertLevel fromId(int id) {
		switch(id) {
		case 1: return warning;
		case 2: return fatal;

		default: return null;
		}
	}
}
