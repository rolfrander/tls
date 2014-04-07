package org.pvv.rolfn.asn1;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;
import org.pvv.rolfn.TestUtils;

public class ASN1PrintableStringTest {

	public final static String ASN1_NO = "13024e4f";
	
	@Test
	public void test() {
		ASN1Object o = ASN1Object.read(ByteBuffer.wrap(TestUtils.hexToByteArray(ASN1_NO)));
		assertTrue(o instanceof ASN1PrintableString);
		assertEquals("NO", o.toString());
	}

}
