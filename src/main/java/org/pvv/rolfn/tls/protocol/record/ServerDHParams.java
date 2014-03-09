package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public class ServerDHParams {
	private byte dh_p[];
	private byte dh_g[];
	private byte dh_Ys[];
	
	public ServerDHParams(ByteBuffer buf) {
		dh_p = ByteBufferUtils.readArray16(buf);
		dh_g = ByteBufferUtils.readArray16(buf);
		dh_Ys = ByteBufferUtils.readArray16(buf);
	}
}