package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;

public class ECCurveTypeTest {

	public static ECCurveType curve(int unsignedByte) {
		byte buf[] = new byte[1];
		buf[0] = (byte)(0xff & unsignedByte);
		return ECCurveType.read(ByteBuffer.wrap(buf));
	}
	
	@Test
	public void testExplicitPrime() {
		assertEquals(ECCurveType.explicit_prime, curve(1));
	}

	@Test
	public void testExplicitChar2() {
		assertEquals(ECCurveType.explicit_char2, curve(2));
	}
	
	@Test
	public void testNamedCurve() {
		assertEquals(ECCurveType.named_curve, curve(3));
	}
	
	@Test
	public void testNull() {
		assertEquals(null, curve(4));
	}
	
}
