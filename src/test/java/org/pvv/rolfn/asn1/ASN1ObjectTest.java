package org.pvv.rolfn.asn1;

import static org.junit.Assert.*;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.Iterator;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import org.pvv.rolfn.TestUtils;

public class ASN1ObjectTest {

	public static final String ASN1_DN = "304d310b3009060355040613024e4f311b3019060355040a0c1248656c6c6572756420496e7465726e6574"
			+ "74310b3009060355040b0c0243413114301206035504030c0b5465737420726f6f742031";
	public static final String PEM_START = "-----BEGIN CERTIFICATE-----";
	public static final String PEM_END   = "-----END CERTIFICATE-----";
	
	@Test
	public void testDN() {
		byte data[] = TestUtils.hexToByteArray(ASN1_DN);
		ASN1Object o = ASN1Object.read(ByteBuffer.wrap(data));
		//o.prettyPrint(0);
		ASN1Sequence o1 = (ASN1Sequence)o;
		Iterator<ASN1Object> iterator = o1.getContent().iterator();
		checkRDN((ASN1Set) iterator.next(), "2.5.4.6",  "NO");
		checkRDN((ASN1Set) iterator.next(), "2.5.4.10", "Hellerud Internett");
		checkRDN((ASN1Set) iterator.next(), "2.5.4.11", "CA");
		checkRDN((ASN1Set) iterator.next(), "2.5.4.3",  "Test root 1");
	}

	private void checkRDN(ASN1Set rdnComponent, String oid, String value) {
		ASN1Sequence o3 = (ASN1Sequence) rdnComponent.getContent().iterator().next();
		Iterator<ASN1Object> iterator = o3.getContent().iterator();
		assertEquals(oid, iterator.next().toString());
		assertEquals(value, iterator.next().toString());
	}

	@Test
	public void testLength() {
		assertEquals(38, ASN1Object.getLength(ByteBuffer.wrap(new byte[] { (byte)38 })));
		assertEquals(435, ASN1Object.getLength(ByteBuffer.wrap(new byte[] { (byte)130, (byte)1, (byte)179 })));
	}
	
	@Test
	public void testCert() throws IOException {
		String filename = this.getClass().getPackage().getName().replace('.', '/')+"/wikipedia.org.crt";
		InputStream in = this.getClass().getClassLoader().getResourceAsStream(filename);
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
		ByteBuffer buf = ByteBuffer.allocate(1024*8);
		
		String line = reader.readLine();
		while(!PEM_START.equals(line)) {
			line = reader.readLine();
		}
		line = reader.readLine();
		while(!PEM_END.equals(line)) {
			buf.put(Base64.decodeBase64(line));
			line = reader.readLine();
		}
		buf.rewind();
		ASN1Object cert = ASN1Object.read(buf);
		//cert.prettyPrint(0);
	}
	
}
