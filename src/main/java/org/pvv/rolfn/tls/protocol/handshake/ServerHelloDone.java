package org.pvv.rolfn.tls.protocol.handshake;

import java.nio.ByteBuffer;

public class ServerHelloDone extends HandshakeMessage {

	public ServerHelloDone() {
		// Empty
	}

	static protected ServerHelloDone read(ByteBuffer buf) {
		return new ServerHelloDone();
	}
	
}
