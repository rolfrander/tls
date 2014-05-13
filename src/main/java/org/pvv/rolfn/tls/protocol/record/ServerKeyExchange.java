package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

/**
 * This message will be sent immediately after the server Certificate message
 * (or the ServerHello message, if this is an anonymous negotiation).
 * <p>
 * The ServerKeyExchange message is sent by the server only when the server
 * Certificate message (if sent) does not contain enough data to allow the
 * client to exchange a premaster secret.
 * </p>
 * 
 * @author RolfRander
 * 
 */
public class ServerKeyExchange extends HandshakeMessage {

	private ServerDHParams dhParams;
	private ServerECDHParams ecdhParams;
	private byte[] rawKeyData;
	private DigitallySigned signedParams;

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.server_key_exchange;
	}

	public static ServerKeyExchange read(ByteBuffer buf, SecurityParameters sp) {
		return new ServerKeyExchange(buf, sp);
	}
	
	private ServerKeyExchange(ByteBuffer buf, SecurityParameters sp) {
		switch (sp.getCipherSuite().getKeyExchangeAlgorithm()) {
		case dh_anon:
			dhParams = ServerDHParams.read(buf);
			break;
		case dhe_dss:
		case dhe_rsa:
		case dhe_psk:
			dhParams = ServerDHParams.read(buf);
			signedParams = DigitallySigned.read(buf);
			break;
		case ecdhe_ecdsa:
		case ecdhe_rsa:
		case ecdh_anon:
		case ecdhe_psk:
			ecdhParams = ServerECDHParams.read(buf);
			signedParams = DigitallySigned.read(buf);
			break;
		case dh_dss:
		case dh_rsa:
		case ecdh_ecdsa:
		case ecdh_rsa:
		case rsa:
		case Null:
		case krb5:
		case psk:
		case rsa_psk:
		case srp_sha:
		case srp_sha_dss:
		case srp_sha_rsa:
			break;
		}
	}

	public ServerDHParams getDhParams() {
		return dhParams;
	}

	public ServerECDHParams getEcdhParams() {
		return ecdhParams;
	}

	public DigitallySigned getSignedParams() {
		return signedParams;
	}

	/**
	 * Key data as encoded in the actual message. Used for verifying signature.
	 * @return
	 */
	public byte[] getRawKeyData() {
		return rawKeyData;
	}	
}
