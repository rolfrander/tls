package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;

public class ProtocolVersionTest {

	@Test
	public void test() {
		assertEquals("SSL 2.0", ProtocolVersion.SSL2_0.toString());
		assertEquals("SSL 3.0", ProtocolVersion.SSL3_0.toString());
		assertEquals("TLS 1.0", ProtocolVersion.TLS1_0.toString());
		assertEquals("TLS 1.1", ProtocolVersion.TLS1_1.toString());
		assertEquals("TLS 1.2", ProtocolVersion.TLS1_2.toString());
		
		assertEquals(ProtocolVersion.TLS1_0, ProtocolVersion.read(ByteBuffer.wrap(new byte[] { (byte)3, (byte)1 })));
	}

}
