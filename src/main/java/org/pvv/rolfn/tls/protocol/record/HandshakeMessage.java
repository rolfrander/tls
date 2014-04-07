package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public class HandshakeMessage {

	public void write(ByteBuffer buf) {
		throw new RuntimeException(this.getClass().getCanonicalName()+".write() not implemented");
	}
	
	public int estimateSize() {
		return -1;
	}
	
	static public void read(TLSRecord msg, SecurityParameters params, HandshakeVisitor v) {
		ByteBuffer buf = ByteBuffer.wrap(msg.getData());
		HandshakeMessage handshake;
		do {
			handshake = HandshakeMessage.read(buf, params, v);
		} while(handshake != null);
	}
	
	static protected HandshakeMessage read(ByteBuffer buf, SecurityParameters params) {
		return HandshakeMessage.read(buf, params, null);
	}
	
	static protected HandshakeMessage read(ByteBuffer buf, SecurityParameters params, HandshakeVisitor v) {
		if(buf.remaining() == 0) {
			return null;
		}
		if(buf.remaining() < 4) {
			throw new RuntimeException("missing data in handshake header, remaining="+buf.remaining());
		}
		HandshakeType msgType = HandshakeType.byid(buf.get());
		int length = ByteBufferUtils.getUnsigned24(buf);
		
		switch(msgType) {
		case hello_request:	return visitAndReturn(HelloRequest.read(buf), v);
		case client_hello:	return visitAndReturn(ClientHello.read(buf, length), v);
			/*
			ClientHello clientHello = ClientHello.read(buf, length);
			params.setClientRandom(clientHello.getRandom());
			return clientHello;
			*/
		case server_hello:	return visitAndReturn(ServerHello.read(buf, length), v);
			/*
			ServerHello serverHello = ServerHello.read(buf, length);
			params.setCipherSuite(serverHello.getCipherSuite());
			params.setServerRandom(serverHello.getRandom());
			return serverHello;
			*/
		case certificate: 	return visitAndReturn(Certificate.read(buf), v);
			/*
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
			*/
		case server_key_exchange: return visitAndReturn(ServerKeyExchange.read(buf, params), v);
		case certificate_request: return visitAndReturn(CertificateRequest.read(buf), v);
		case server_hello_done:   return visitAndReturn(ServerHelloDone.read(buf), v);
		case certificate_verify:  return visitAndReturn(CertificateVerify.read(buf), v);
		case client_key_exchange: return visitAndReturn(ClientKeyExchange.read(buf, params), v);
		case finished:            return visitAndReturn(Finished.read(buf, params), v);
		}
		throw new IllegalStateException("unknown message type: "+msgType);
	}

	private static HandshakeMessage visitAndReturn(Finished read, HandshakeVisitor v) {
		if(v != null) v.finished(read);
		return read;
	}

	private static HandshakeMessage visitAndReturn(ClientKeyExchange clientKeyExchange, HandshakeVisitor v) {
		if(v != null) v.clientKeyExchange(clientKeyExchange);
		return clientKeyExchange;
	}

	private static HandshakeMessage visitAndReturn(CertificateVerify certificateVerify, HandshakeVisitor v) {
		if(v != null) v.certificateVerify(certificateVerify);
		return certificateVerify;
	}

	private static HandshakeMessage visitAndReturn(ServerHelloDone serverHelloDone, HandshakeVisitor v) {
		if(v != null) v.serverHelloDone(serverHelloDone);
		return serverHelloDone;
	}

	private static HandshakeMessage visitAndReturn(ServerKeyExchange serverKeyExchange, HandshakeVisitor v) {
		if(v != null) v.serverKeyExchange(serverKeyExchange);
		return serverKeyExchange;
	}

	private static HandshakeMessage visitAndReturn(CertificateRequest certReq, HandshakeVisitor v) {
		if(v != null) v.certificateRequest(certReq);
		return certReq;
	}

	private static HandshakeMessage visitAndReturn(Certificate cert, HandshakeVisitor v) {
		if(v != null) v.certificate(cert);
		return cert;
	}

	private static HandshakeMessage visitAndReturn(ServerHello srvHello, HandshakeVisitor v) {
		if(v != null) v.serverHello(srvHello);
		return srvHello;
	}

	private static HandshakeMessage visitAndReturn(HelloRequest hello, HandshakeVisitor v) {
		if(v != null) v.helloRequest(hello);
		return hello;
	}

	private static HandshakeMessage visitAndReturn(ClientHello clientHello, HandshakeVisitor v) {
		if(v != null) v.clientHello(clientHello);
		return clientHello;
	}
}
