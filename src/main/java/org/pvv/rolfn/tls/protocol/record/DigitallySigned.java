package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public class DigitallySigned {
	private SignatureAndHashAlgorithm algo;
	private byte[] signature;
	
	private DigitallySigned(ByteBuffer buf) {
		algo = SignatureAndHashAlgorithm.read(buf);
		signature = ByteBufferUtils.readArray16(buf);
	}

	static protected DigitallySigned read(ByteBuffer buf) {
		return new DigitallySigned(buf);
	}
	
	public SignatureAndHashAlgorithm getAlgo() {
		return algo;
	}

	public byte[] getSignature() {
		return signature;
	}

}
