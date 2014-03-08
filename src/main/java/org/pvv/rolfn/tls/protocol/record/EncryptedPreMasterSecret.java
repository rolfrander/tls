package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class EncryptedPreMasterSecret {

	private byte[] data;
	public EncryptedPreMasterSecret(ByteBuffer buf) {
		data = RecordUtils.readArray16(buf);
	}

}
