package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;
import org.pvv.rolfn.TestUtils;

public class NamedCurveTest {

	@Test
	public void test() {
		ByteBuffer buf = ByteBuffer.wrap(TestUtils.hexToByteArray(
				"0001"   // sect163k1
				+ "0002" // sect163r1
				+ "0019" // secp521r1
				+ "001d" // unassigned
				+ "fe00" // reserved
				+ "feff" // reserved
				+ "ff01" // explicit prime curve
				+ "ff02" // explicit char2 curve
				+ "ffff"));
		assertEquals(NamedCurve.sect163k1, NamedCurve.read(buf));
		assertEquals(NamedCurve.sect163r1, NamedCurve.read(buf));
		assertEquals(NamedCurve.secp521r1, NamedCurve.read(buf));
		assertEquals(null, NamedCurve.read(buf));
		assertEquals(null, NamedCurve.read(buf));
		assertEquals(null, NamedCurve.read(buf));
		assertEquals(NamedCurve.arbitrary_explicit_prime_curves, NamedCurve.read(buf));
		assertEquals(NamedCurve.arbitrary_explicit_char2_curves, NamedCurve.read(buf));
		assertEquals(null, NamedCurve.read(buf));
	}

}
