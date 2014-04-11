package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

/**
 * This message is used to provide explicit verification of a client
 * certificate. This message is only sent following a client certificate that
 * has signing capability (i.e., all certificates except those containing fixed
 * Diffie-Hellman parameters). When sent, it MUST immediately follow the client
 * key exchange message.
 * 
 * @author RolfRander
 * @see http://tools.ietf.org/html/rfc5246#section-7.4.8
 * @see http://tools.ietf.org/html/rfc4346#section-7.4.8
 * 
 */
public class CertificateVerify extends HandshakeMessage {
	private DigitallySigned signature;

	public CertificateVerify(ByteBuffer buf) {
		signature = DigitallySigned.read(buf);
	}

	public static CertificateVerify read(ByteBuffer buf) {
		return new CertificateVerify(buf);
	}
	
	public DigitallySigned getSignature() {
		return signature;
	}
}
