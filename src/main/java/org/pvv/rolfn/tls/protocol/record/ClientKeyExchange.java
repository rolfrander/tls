package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.apache.commons.lang3.NotImplementedException;

public class ClientKeyExchange implements HandshakeMessage {

	private EncryptedPreMasterSecret epms;
	private ClientDiffieHellmanPublic clientDHpub;

	public ClientKeyExchange(ByteBuffer buf, SecurityParameters param) {
		switch(param.getCipherSuite().getKeyExchangeAlgorithm()) {
		case rsa:
			epms = new EncryptedPreMasterSecret(buf);
			break;
		case dhe_dss:
		case dhe_rsa:
		case dh_dss:
		case dh_rsa:
		case dh_anon:
			clientDHpub = new ClientDiffieHellmanPublic(buf, param);
			break;
		case ec_diffie_hellman:
			throw new NotImplementedException("ECDH key exchange");
		}
	}

}
