package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class ServerKeyExchange implements HandshakeMessage {

	private ServerDHParams params;
	private byte client_random[];
	private byte server_random[];
	
	public ServerKeyExchange(ByteBuffer buf, SecurityParameters sp) {
		switch(sp.getCipherSuite().getKeyExchangeAlgorithm()) {
		case dh_anon:
			params = new ServerDHParams(buf);
			break;
		case dhe_dss:
		case dhe_rsa:
			params = new ServerDHParams(buf);
			break;
		case ec_diffie_hellman:
			break;
		case dh_dss:
		case dh_rsa:
		case rsa:
			break;
		}
	}

}
