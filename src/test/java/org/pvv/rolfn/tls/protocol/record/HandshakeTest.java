package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.junit.After;
import org.junit.Before;
import org.pvv.rolfn.tls.protocol.TLSConnection;

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
		HandshakeMessage h = TLSConnection.readHandshake(buf, params, null);
		return h;
	}

}
