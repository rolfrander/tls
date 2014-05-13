package org.pvv.rolfn.tls.protocol;

import java.nio.ByteBuffer;

import org.junit.After;
import org.junit.Before;
import org.pvv.rolfn.tls.protocol.TLSConnection;
import org.pvv.rolfn.tls.protocol.record.HandshakeMessage;
import org.pvv.rolfn.tls.protocol.record.ProtocolVersion;
import org.pvv.rolfn.tls.protocol.record.SecurityParameters;

public class HandshakeTest {

	protected SecurityParameters params;
	protected TLSConnection conn;

	@Before
	public void setUpParams() {
		params = new SecurityParameters();		
		conn = new TLSConnection(ProtocolVersion.TLS1_2, null);
	}
	
	@After
	public void removeParams() {
		params = null;
	}
	
	protected HandshakeMessage parseHandshake(byte[] message) {
		ByteBuffer buf = ByteBuffer.wrap(message);
		HandshakeMessage h = conn.readHandshake(buf, params, null);
		return h;
	}

}
