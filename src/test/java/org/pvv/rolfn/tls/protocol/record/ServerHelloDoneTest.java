package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.List;

import org.junit.Test;
import org.pvv.rolfn.TestUtils;

public class ServerHelloDoneTest extends HandshakeTest {

	public static final String SERVER_HELLO_DONE = "0e000000";
	
	@Test
	public void test() {
		HandshakeMessage message = parseHandshake(TestUtils.hexToByteArray(SERVER_HELLO_DONE));
		assertTrue(message instanceof ServerHelloDone);
	}

}
