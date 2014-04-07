package org.pvv.rolfn.asn1;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;

public class ASN1IntegerTest {

	@Test
	public void testReadInt() {
		assertInt(1, new byte[] { (byte) 0x1 });
		assertInt(256, new byte[] { (byte) 0x1, (byte)0x00 });
		assertInt(65536, new byte[] { (byte) 0x1, (byte)0x00, (byte)0x00 });
		assertInt(16777216, new byte[] { (byte) 0x1, (byte)0x00, (byte)0x00, (byte)0x00 });
		assertInt(-1, new byte[] { (byte) 0xff });
		assertInt(-256, new byte[] { (byte) 0xff, (byte) 0x00 });
		assertInt(-16777216, new byte[] { (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00 });
		assertInt(-65536, new byte[] { (byte) 0xff, (byte) 0x00, (byte) 0x00 });
		assertInt(255, new byte[] { (byte) 0x00, (byte) 0xff });
	}

	private void assertInt(int value, byte[] data) {
		assertEquals(value, new ASN1Integer(data.length, ByteBuffer.wrap(data)).getValue().intValue());
	}

}
