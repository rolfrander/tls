package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import javax.crypto.interfaces.DHPublicKey;

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

	public ClientDiffieHellmanPublic(DHPublicKey key) {
		dh_Yc = key.getY().toByteArray();
	}
	
	static protected ClientDiffieHellmanPublic read(ByteBuffer buf, SecurityParameters param) {
		return new ClientDiffieHellmanPublic(buf, param);
	}

	protected void write(ByteBuffer buf) {
		ByteBufferUtils.writeArray16(buf, dh_Yc);
	}

	public int estimateSize() {
		return dh_Yc.length+2;
	}
}
