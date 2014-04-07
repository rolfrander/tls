package org.pvv.rolfn.asn1;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.Iterator;

import org.junit.Test;
import org.pvv.rolfn.TestUtils;

public class OIDTest {

	public static final String OID_shaWithRSAEncryption = "2a864886f70d010105";
	public static final String OID_nsCertExtsComment = "6086480186f842010d";
	public static final String ASN1_OID_countryName = "0603550406";
	
	@Test
	public void testShaRSA() {
		byte data[] = TestUtils.hexToByteArray(OID_shaWithRSAEncryption);
		OID oid = OID.read(data.length, ByteBuffer.wrap(data));
		assertEquals("1.2.840.113549.1.1.5", oid.toString());
	}

	@Test
	public void testNsComment() {
		byte data[] = TestUtils.hexToByteArray(OID_nsCertExtsComment);
		OID oid = OID.read(data.length, ByteBuffer.wrap(data));
		assertEquals("2.16.840.1.113730.1.13", oid.toString());
	}
	
	@Test
	public void testEquals() {
		byte data[] = TestUtils.hexToByteArray(OID_nsCertExtsComment);
		OID oid1 = OID.read(data.length, ByteBuffer.wrap(data));
		OID oid2 = OID.read(data.length, ByteBuffer.wrap(data));
		assertTrue(oid1 == oid2);
	}
	
	@Test
	public void testAsn1CN() {
		byte data[] = TestUtils.hexToByteArray(ASN1_OID_countryName);
		ASN1Object o = ASN1Object.read(ByteBuffer.wrap(data));
		assertTrue(o instanceof OID);
		OID oid = (OID)o;
		assertEquals("2.5.4.6", oid.toString());
	}

	@Test
	public void testName() {
		OID oid1 = OID.getById(1, 2, 3);
		OID oid2 = OID.getById(1, 2, 4);
		oid1.setName("FOO");
		assertEquals("FOO", oid1.getName());
		assertTrue(oid1 == OID.getByName("FOO"));
		oid2.setName("FOO");
		assertTrue(oid2 == OID.getByName("FOO"));
		assertEquals(null, oid1.getName());
		oid2.setName("BAR");
		assertEquals("BAR", oid2.getName());
		assertTrue(oid2 == OID.getByName("BAR"));
		assertTrue(null == OID.getByName("FOO"));
	}
	
}
