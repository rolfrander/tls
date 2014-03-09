package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public class DigitallySigned {
	private SignatureAndHashAlgorithm algo;
	private byte[] signature;
	
	protected DigitallySigned(ByteBuffer buf) {
		algo = new SignatureAndHashAlgorithm(buf);
		signature = ByteBufferUtils.readArray16(buf);
	}

}
