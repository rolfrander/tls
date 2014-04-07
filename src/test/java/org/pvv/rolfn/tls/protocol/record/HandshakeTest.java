package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.junit.After;
import org.junit.Before;

public class HandshakeTest {

	protected SecurityParameters params;

	@Before
	public void setUpParams() {
		params = new SecurityParameters();		
	}
	
	@After
	public void removeParams() {
		params = null;
	}
	
	protected HandshakeMessage parseHandshake(byte[] message) {
		ByteBuffer buf = ByteBuffer.wrap(message);
		HandshakeMessage h = HandshakeMessage.read(buf, params);
		return h;
	}

}
