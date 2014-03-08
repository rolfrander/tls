package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class CertificateVerify implements HandshakeMessage {
	private DigitallySigned signature;
	
	public CertificateVerify(ByteBuffer buf) {
		signature = new DigitallySigned(buf);
	}

}
