package org.pvv.rolfn.tls.protocol;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.log4j.Logger;
import org.pvv.rolfn.tls.protocol.record.Certificate;
import org.pvv.rolfn.tls.protocol.record.CertificateRequest;
import org.pvv.rolfn.tls.protocol.record.CertificateVerify;
import org.pvv.rolfn.tls.protocol.record.CipherSuite;
import org.pvv.rolfn.tls.protocol.record.ClientHello;
import org.pvv.rolfn.tls.protocol.record.ClientKeyExchange;
import org.pvv.rolfn.tls.protocol.record.ConnectionEnd;
import org.pvv.rolfn.tls.protocol.record.Finished;
import org.pvv.rolfn.tls.protocol.record.HandshakeVisitor;
import org.pvv.rolfn.tls.protocol.record.HelloRequest;
import org.pvv.rolfn.tls.protocol.record.SecurityParameters;
import org.pvv.rolfn.tls.protocol.record.ServerHello;
import org.pvv.rolfn.tls.protocol.record.ServerHelloDone;
import org.pvv.rolfn.tls.protocol.record.ServerKeyExchange;

public class DefaultHandshakeHandler implements HandshakeVisitor {
	static private final Logger log = Logger.getLogger(DefaultHandshakeHandler.class);
	
	static private enum HandshakeState {
		clean, negotiating, handshakeDone
	};
	
	private HandshakeState state = HandshakeState.clean;
	private SecurityParameters params;
	private TLSConnection connection;
	private SecureRandom random;
	
	public DefaultHandshakeHandler(TLSConnection connection, SecurityParameters params) {
		this.params = params;
		this.connection = connection;
		try {
			this.random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			log.fatal("error getting SHA1PRNG", e);
			throw new RuntimeException(e);
		}
	}
	
	@Override
	public boolean isReadyToTransmitApplicationData() {
		return state == HandshakeState.handshakeDone;
	}
	
	@Override
	public void helloRequest(HelloRequest hello) {
		// ignore helloRequest if in the middle of negotiation
		if(state == HandshakeState.negotiating) {
			return;
		}
		state = HandshakeState.negotiating;
		if(params.getEntity() == ConnectionEnd.client) {
			ClientHello clientHello = new ClientHello(params.getProtocolVersion(), random);
			clientHello.addCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
			clientHello.addCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
			// TODO: session id?
			connection.writeMessage(clientHello);
		}
	}

	@Override
	public void clientHello(ClientHello clientHello) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void serverHello(ServerHello srvHello) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void certificate(Certificate cert) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void serverKeyExchange(ServerKeyExchange serverKeyExchange) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void certificateRequest(CertificateRequest certReq) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void serverHelloDone(ServerHelloDone serverHelloDone) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void clientKeyExchange(ClientKeyExchange clientKeyExchange) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void certificateVerify(CertificateVerify certificateVerify) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void finished(Finished finished) {
		// TODO Auto-generated method stub
		
	}

}
