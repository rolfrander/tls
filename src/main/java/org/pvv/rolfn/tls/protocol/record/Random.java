package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class Random {

	//private int gmt_unix_time;
	private byte[] randomBytes;

	protected Random(ByteBuffer buf) {
		//gmt_unix_time = buf.getInt();
		randomBytes = new byte[32];
		buf.get(randomBytes);
	}
	
	public byte[] getData() {
		return randomBytes;
	}
}
