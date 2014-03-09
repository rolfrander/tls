package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.pvv.rolfn.io.ByteBufferUtils;

public class CertificateRequest implements HandshakeMessage {
	private ClientCertificateType certificateTypes[];
	private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms;
	private List<DistinguishedName> distinguishedNames;
	
	public CertificateRequest(ByteBuffer buf) {
		byte[] array = ByteBufferUtils.readArray8(buf);
		this.certificateTypes = new ClientCertificateType[array.length];
		int i=0;
		for(int type: array) {
			this.certificateTypes[i++] = ClientCertificateType.fromId(type & 0xff);
		}
		
		int len = ByteBufferUtils.getUnsignedShort(buf);
		int start = buf.arrayOffset();
		supportedSignatureAndHashAlgorithms = new ArrayList<SignatureAndHashAlgorithm>();
		while(buf.arrayOffset() < (start+len)) {
			supportedSignatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(buf));
		}
		
		len = ByteBufferUtils.getUnsignedShort(buf);
		start = buf.arrayOffset();
		distinguishedNames = new ArrayList<DistinguishedName>();
		while(buf.arrayOffset() < (start+len)) {
			distinguishedNames.add(new DistinguishedName(buf));
		}
	}

}
