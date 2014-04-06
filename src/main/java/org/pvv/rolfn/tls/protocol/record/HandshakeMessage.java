package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public class HandshakeMessage {

	static protected HandshakeMessage read(ByteBuffer buf, SecurityParameters params) {
		HandshakeType msgType = HandshakeType.byid(buf.get());
		int length = ByteBufferUtils.getUnsigned24(buf);
		
		switch(msgType) {
		case hello_request:	return HelloRequest.read(buf);
		case client_hello:
			ClientHello clientHello = ClientHello.read(buf, length);
			params.setClientRandom(clientHello.getRandom());
			return clientHello;
			
		case server_hello:
			ServerHello serverHello = ServerHello.read(buf, length);
			params.setCipherSuite(serverHello.getCipherSuite());
			params.setServerRandom(serverHello.getRandom());
			return serverHello;
			
		case certificate: 
			// is this a server-certificate or a client certificate?
			// am I a server or a client?
			Certificate certificate = Certificate.read(buf);
			switch(params.getEntity()) {
			case client:
				params.setServerCertificate(certificate);
				break;
			case server:
				params.setClientCertificate(certificate);
				break;
			}
			return certificate;
			
		case server_key_exchange: return ServerKeyExchange.read(buf, params);
		case certificate_request: return CertificateRequest.read(buf);
		case server_hello_done:   return ServerHelloDone.read(buf);
		case certificate_verify:  return CertificateVerify.read(buf);
		case client_key_exchange: return ClientKeyExchange.read(buf, params);
		case finished:            return Finished.read(buf, params);
		}
		return null;
	}
}
