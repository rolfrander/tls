package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class CertificateRequest implements HandshakeMessage {
	private ClientCertificateType certificateTypes[];
	private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms;
	private List<DistinguishedName> distinguishedNames;
	
	public CertificateRequest(ByteBuffer buf) {
		byte[] array = RecordUtils.readArray8(buf);
		this.certificateTypes = new ClientCertificateType[array.length];
		int i=0;
		for(int type: array) {
			this.certificateTypes[i++] = ClientCertificateType.fromId(type & 0xff);
		}
		
		int len = RecordUtils.getUnsignedShort(buf);
		int start = buf.arrayOffset();
		supportedSignatureAndHashAlgorithms = new ArrayList<SignatureAndHashAlgorithm>();
		while(buf.arrayOffset() < (start+len)) {
			supportedSignatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(buf));
		}
		
		len = RecordUtils.getUnsignedShort(buf);
		start = buf.arrayOffset();
		distinguishedNames = new ArrayList<DistinguishedName>();
		while(buf.arrayOffset() < (start+len)) {
			distinguishedNames.add(new DistinguishedName(buf));
		}
	}

}
