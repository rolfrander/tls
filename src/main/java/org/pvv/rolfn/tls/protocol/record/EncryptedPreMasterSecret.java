package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public class EncryptedPreMasterSecret {

	private byte[] data;
	public EncryptedPreMasterSecret(ByteBuffer buf) {
		data = ByteBufferUtils.readArray16(buf);
	}

}
