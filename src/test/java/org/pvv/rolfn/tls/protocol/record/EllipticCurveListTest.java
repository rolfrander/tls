package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.Iterator;

import org.junit.Test;
import org.pvv.rolfn.TestUtils;

public class EllipticCurveListTest {

	public static final String TLS_EC_LIST = "000100020003";
	
	@Test
	public void test() {
		int ecListLen = (TLS_EC_LIST.length() >> 1);
		String ecList = String.format("%04x%s", ecListLen, TLS_EC_LIST);
		EllipticCurveList list = EllipticCurveList.read(ByteBuffer.wrap(TestUtils.hexToByteArray(ecList)));
		assertEquals(TLS_EC_LIST.length()/4, list.size());
		Iterator<NamedCurve> i = list.iterator();
		assertEquals(NamedCurve.sect163k1, i.next());
		assertEquals(NamedCurve.sect163r1, i.next());
		assertEquals(NamedCurve.sect163r2, i.next());
	}

}
