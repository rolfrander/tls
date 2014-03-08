package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class ServerDHParams {
	private byte dh_p[];
	private byte dh_g[];
	private byte dh_Ys[];
	
	public ServerDHParams(ByteBuffer buf) {
		dh_p = RecordUtils.readArray16(buf);
		dh_g = RecordUtils.readArray16(buf);
		dh_Ys = RecordUtils.readArray16(buf);
	}
}