package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;
import org.pvv.rolfn.TestUtils;

public class ECCurveTest {

	public static final String TLS_CURVE_DATA = "04010203040405060708";
	public static final String TLS_CURVE_A = "01020304";
	public static final String TLS_CURVE_B = "05060708";
	
	@Test
	public void test() {
		ECCurve curve = ECCurve.read(ByteBuffer.wrap(TestUtils.hexToByteArray(TLS_CURVE_DATA)));
		assertArrayEquals(TestUtils.hexToByteArray(TLS_CURVE_A), curve.getA());
		assertArrayEquals(TestUtils.hexToByteArray(TLS_CURVE_B), curve.getB());
	}

}
