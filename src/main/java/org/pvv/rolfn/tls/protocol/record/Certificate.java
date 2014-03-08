package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class Certificate implements HandshakeMessage {
	private int length;
	private byte[] data;
	
	public Certificate(ByteBuffer buf) {
		length = buf.getInt();
		data = new byte[length];
		buf.get(data);
	}

	public byte[] getData() {
		return data;
	}

	public boolean hasPublicDHValue() {
		return false;
	}
}
