package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public class EncryptedPreMasterSecret {

	private byte[] data;
	private EncryptedPreMasterSecret(ByteBuffer buf) {
		data = ByteBufferUtils.readArray16(buf);
	}

	static protected EncryptedPreMasterSecret read(ByteBuffer buf) {
		return new EncryptedPreMasterSecret(buf);
	}
	
	public byte[] getData() {
		return data;
	}

	protected void write(ByteBuffer buf) {
		ByteBufferUtils.writeArray16(buf, data);
	}

	public int estimateSize() {
		return data.length+2;
	}
}
