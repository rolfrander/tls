package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class ClientKeyExchange extends HandshakeMessage {

	private EncryptedPreMasterSecret epms = null;
	private ClientDiffieHellmanPublic clientDHpub = null;

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.client_key_exchange;
	}

	private ClientKeyExchange(ByteBuffer buf, SecurityParameters param) {
		KeyExchangeAlgorithm kxAlg = param.getCipherSuite().getKeyExchangeAlgorithm();
		switch(kxAlg) {
		case rsa:
			epms = EncryptedPreMasterSecret.read(buf);
			break;
		case dhe_dss:
		case dhe_rsa:
		case dh_dss:
		case dh_rsa:
		case dh_anon:
		case dhe_psk:
			clientDHpub = ClientDiffieHellmanPublic.read(buf, param);
			break;
		case ecdh_anon:
		case ecdh_ecdsa:
		case ecdh_rsa:
		case ecdhe_ecdsa:
		case ecdhe_rsa:
		case ecdhe_psk:
			// TODO client key exchange ecdh
			throw new RuntimeException("ECDH key exchange not implemented");
		default:
			throw new RuntimeException("no ClientKeyExchange for "+kxAlg);
		}
	}
	
	@Override
	public int estimateSize() {
		if(epms != null) {
			return epms.estimateSize();
		} else if(clientDHpub != null) {
			return clientDHpub.estimateSize();
		} else {
			return 0;
		}
	}

	public ClientKeyExchange(EncryptedPreMasterSecret secret) {
		epms = secret;
	}
	
	public ClientKeyExchange(ClientDiffieHellmanPublic dh) {
		clientDHpub = dh;
	}
	
	static public ClientKeyExchange read(ByteBuffer buf, SecurityParameters param) {
		return new ClientKeyExchange(buf, param);
	}

	@Override
	protected void write(ByteBuffer buf) {
		if(epms != null) {
			epms.write(buf);
		} else if(clientDHpub != null) {
			clientDHpub.write(buf);
		}
	}

	public EncryptedPreMasterSecret getEpms() {
		return epms;
	}

	public ClientDiffieHellmanPublic getClientDHpub() {
		return clientDHpub;
	}
}
