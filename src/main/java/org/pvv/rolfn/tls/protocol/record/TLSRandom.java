package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Random;

public class TLSRandom {

	//private int gmt_unix_time;
	private byte[] randomBytes;

	private TLSRandom(ByteBuffer buf) {
		//gmt_unix_time = buf.getInt();
		randomBytes = new byte[32];
		buf.get(randomBytes);
	}
	
	public TLSRandom(Random random) {
		ByteBuffer buf = ByteBuffer.allocate(32);
		buf.order(ByteOrder.BIG_ENDIAN);
		long ms = System.currentTimeMillis();
		int seconds = (int)(ms/1000);
		buf.putInt(seconds);
		for(int i=0; i<7; i++) {
			buf.putInt(random.nextInt());
		}
	}

	static protected TLSRandom read(ByteBuffer buf) {
		return new TLSRandom(buf);
	}
	
	public byte[] getData() {
		return randomBytes;
	}

	public void write(ByteBuffer buf) {
		buf.put(randomBytes);
	}
}
