package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class ServerHelloDone extends HandshakeMessage {

	public ServerHelloDone() {
		// Empty
	}

	public static ServerHelloDone read(ByteBuffer buf) {
		return new ServerHelloDone();
	}
	
}
