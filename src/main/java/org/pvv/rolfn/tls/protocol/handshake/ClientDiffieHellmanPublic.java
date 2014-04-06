package org.pvv.rolfn.tls.protocol.handshake;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public class ClientDiffieHellmanPublic {
	private byte[] dh_Yc;
	
	private ClientDiffieHellmanPublic(ByteBuffer buf, SecurityParameters param) {
		if(param.getClientCertificate().hasPublicDHValue()) {
			// do nothing, DH-parameter is in certificate
		} else {
			dh_Yc = ByteBufferUtils.readArray16(buf);
		}
	}

	static protected ClientDiffieHellmanPublic read(ByteBuffer buf, SecurityParameters param) {
		return new ClientDiffieHellmanPublic(buf, param);
	}
}
