package org.pvv.rolfn.tls.protocol.record;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import org.pvv.rolfn.io.ByteBufferUtils;

/**
 * Certificate from server or client.
 * <p>
 * <strong>Server certificates</strong>
 * </p>
 * <p>
 * The server MUST send a Certificate message whenever the agreed- upon key
 * exchange method uses certificates for authentication (this includes all key
 * exchange methods defined in this document except DH_anon). This message will
 * always immediately follow the ServerHello message.
 * </p>
 * <p>
 * This message conveys the server's certificate chain to the client.
 * </p>
 * <p>
 * The certificate MUST be appropriate for the negotiated cipher suite's key
 * exchange algorithm and any negotiated extensions.
 * </p>
 * 
 * @author RolfRander
 * 
 */
public class Certificate extends HandshakeMessage {

	private List<X509Certificate> certList = new ArrayList<X509Certificate>();
	private X509Certificate myCert;

	private Certificate(ByteBuffer buf) {
		try {
			int length = ByteBufferUtils.getUnsigned24(buf);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			int start = buf.position();
			while ((start + length) > buf.position()) {
				InputStream bufInput = ByteBufferUtils.asInputStream(ByteBufferUtils.subBuffer24(buf));
				certList.add((X509Certificate) cf.generateCertificate(bufInput));
			}
			myCert = certList.get(0);
		} catch (CertificateException e) {
			// TODO something smart here...
		}
	}
	
	protected static Certificate read(ByteBuffer buf) {
		return new Certificate(buf);
	}

	public X509Certificate getCertificate() {
		return myCert;
	}
	
	public boolean hasPublicDHValue() {
		// don't know how to support this...
		return false;
	}
}
