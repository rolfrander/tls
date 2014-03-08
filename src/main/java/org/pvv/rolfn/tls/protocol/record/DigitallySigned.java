package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class DigitallySigned {
	private SignatureAndHashAlgorithm algo;
	private byte[] signature;
	
	protected DigitallySigned(ByteBuffer buf) {
		algo = new SignatureAndHashAlgorithm(buf);
		signature = RecordUtils.readArray16(buf);
	}

}
