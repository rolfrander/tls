package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class DistinguishedName {
	private byte[] data;
	
	protected DistinguishedName(ByteBuffer buf) {
		data = RecordUtils.readArray16(buf);
	}
}
