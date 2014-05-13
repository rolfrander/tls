package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;
import org.pvv.rolfn.tls.protocol.HandshakeTest;

public class HelloRequestTest extends HandshakeTest {

	public final static byte[] HELLO_REQUEST = new byte[] {0,0,0,0};
	
	@Test
	public void test() {
		HandshakeMessage msg = parseHandshake(HELLO_REQUEST);
		assertTrue(msg instanceof HelloRequest);
	}

}
