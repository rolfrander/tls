package org.pvv.rolfn.tls.protocol.handshake;

import java.nio.ByteBuffer;

import org.apache.commons.lang3.NotImplementedException;

public class ClientKeyExchange extends HandshakeMessage {

	private EncryptedPreMasterSecret epms = null;
	private ClientDiffieHellmanPublic clientDHpub = null;

	private ClientKeyExchange(ByteBuffer buf, SecurityParameters param) {
		switch(param.getCipherSuite().getKeyExchangeAlgorithm()) {
		case rsa:
			epms = EncryptedPreMasterSecret.read(buf);
			break;
		case dhe_dss:
		case dhe_rsa:
		case dh_dss:
		case dh_rsa:
		case dh_anon:
			clientDHpub = ClientDiffieHellmanPublic.read(buf, param);
			break;
		case ecdh_anon:
		case ecdh_ecdsa:
		case ecdh_rsa:
		case ecdhe_ecdsa:
		case ecdhe_rsa:
			// TODO client key exchange ecdh
			throw new NotImplementedException("ECDH key exchange");
		}
	}
	
	static public ClientKeyExchange read(ByteBuffer buf, SecurityParameters param) {
		return new ClientKeyExchange(buf, param);
	}

	public EncryptedPreMasterSecret getEpms() {
		return epms;
	}

	public ClientDiffieHellmanPublic getClientDHpub() {
		return clientDHpub;
	}
}
