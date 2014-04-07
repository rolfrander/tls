package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.ByteBuffer;

import org.junit.Test;
import org.pvv.rolfn.TestUtils;
import org.pvv.rolfn.asn1.ASN1Parser;
import org.pvv.rolfn.asn1.OID;

public class CertificateRequestTest extends HandshakeTest {

	static {
		try {
			String classpathResource = "org/pvv/rolfn/asn1/oid.asn1";
			ASN1Parser.readASN1DefinitionsFromClasspath(classpathResource);
		} catch (IOException e) {
		}
	}
	
	public static final String CERTIFICATE_REQUEST = "03010240002006010602060305010502050304010402040303010302030302010202020301010051004f304d310b3009060355040613024e4f311b3019060355040a0c1248656c6c6572756420496e7465726e657474310b3009060355040b0c0243413114301206035504030c0b5465737420726f6f742031";
	
	@Test
	public void test() {
		CertificateRequest req = CertificateRequest.read(ByteBuffer.wrap(TestUtils.hexToByteArray(CERTIFICATE_REQUEST)));
		ClientCertificateType[] types = req.getCertificateTypes();
		assertEquals(ClientCertificateType.rsa_sign, types[0]);
		assertEquals(ClientCertificateType.dss_sign, types[1]);
		assertEquals(ClientCertificateType.ecdsa_sign, types[2]);
		assertEquals(16, req.getSupportedSignatureAndHashAlgorithms().size());
		
		DistinguishedName n = new DistinguishedName();
		n.addRDN(OID.getById(2,5,4,6), "NO")
		.addRDN(OID.getById(2,5,4,10), "Hellerud Internett")
		.addRDN(OID.getById(2,5,4,11), "CA")
		.addRDN(OID.getById(2,5,4,3), "Test root 1");
		
		assertEquals(n, req.getDistinguishedNames().get(0));
		
	}

}
