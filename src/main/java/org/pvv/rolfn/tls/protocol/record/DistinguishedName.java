package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public class DistinguishedName {
	private byte[] data;
	
	protected DistinguishedName(ByteBuffer buf) {
		data = ByteBufferUtils.readArray16(buf);
	}
}
