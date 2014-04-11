package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.pvv.rolfn.io.ByteBufferUtils;

/**
 * A non-anonymous server can optionally request a certificate from the client,
 * if appropriate for the selected cipher suite. This message, if sent, will
 * immediately follow the ServerKeyExchange message (if it is sent; otherwise,
 * this message follows the server's Certificate message).
 * 
 * @author RolfRander
 * 
 */
public class CertificateRequest extends HandshakeMessage {
	/**
	 * A list of the types of certificate types that the client may offer.
	 */
	private ClientCertificateType certificateTypes[];

	/**
	 * A list of the hash/signature algorithm pairs that the server is able to
	 * verify, listed in descending order of preference.
	 */
	private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms;

	/**
	 * A list of the distinguished names [X501] of acceptable
	 * certificate_authorities, represented in DER-encoded format. These
	 * distinguished names may specify a desired distinguished name for a root
	 * CA or for a subordinate CA; thus, this message can be used to describe
	 * known roots as well as a desired authorization space. If the
	 * certificate_authorities list is empty, then the client MAY send any
	 * certificate of the appropriate ClientCertificateType, unless there is
	 * some external arrangement to the contrary.
	 */
	private List<DistinguishedName> distinguishedNames;

	private CertificateRequest(ByteBuffer buf) {
		byte[] array = ByteBufferUtils.readArray8(buf);
		this.certificateTypes = new ClientCertificateType[array.length];
		int i = 0;
		for (int type : array) {
			this.certificateTypes[i++] = ClientCertificateType.fromId(type & 0xff);
		}

		int len = ByteBufferUtils.getUnsignedShort(buf);
		int start = buf.position();
		supportedSignatureAndHashAlgorithms = new ArrayList<SignatureAndHashAlgorithm>();
		while (buf.position() < (start + len)) {
			supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.read(buf));
		}

		len = ByteBufferUtils.getUnsignedShort(buf);
		start = buf.position();
		distinguishedNames = new ArrayList<DistinguishedName>();
		while (buf.position() < (start + len)) {
			// not sure why this len is included, the ASN.1-coding of each DN also starts with len...
			int dnLen = ByteBufferUtils.getUnsignedShort(buf);
			distinguishedNames.add(DistinguishedName.read(buf));
		}
	}

	public static CertificateRequest read(ByteBuffer buf) {
		return new CertificateRequest(buf);
	}
	
	public ClientCertificateType[] getCertificateTypes() {
		return certificateTypes;
	}

	public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
		return supportedSignatureAndHashAlgorithms;
	}

	public List<DistinguishedName> getDistinguishedNames() {
		return distinguishedNames;
	}

	
}
