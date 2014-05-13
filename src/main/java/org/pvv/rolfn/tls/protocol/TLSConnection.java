package org.pvv.rolfn.tls.protocol;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.pvv.rolfn.io.ByteBufferUtils;
import org.pvv.rolfn.tls.crypto.Prf;
import org.pvv.rolfn.tls.protocol.record.Alert;
import org.pvv.rolfn.tls.protocol.record.AlertDescription;
import org.pvv.rolfn.tls.protocol.record.AlertLevel;
import org.pvv.rolfn.tls.protocol.record.Certificate;
import org.pvv.rolfn.tls.protocol.record.CertificateRequest;
import org.pvv.rolfn.tls.protocol.record.CertificateVerify;
import org.pvv.rolfn.tls.protocol.record.ChangeCipherSpec;
import org.pvv.rolfn.tls.protocol.record.CipherSuite;
import org.pvv.rolfn.tls.protocol.record.ClientHello;
import org.pvv.rolfn.tls.protocol.record.ClientKeyExchange;
import org.pvv.rolfn.tls.protocol.record.ConnectionEnd;
import org.pvv.rolfn.tls.protocol.record.ContentType;
import org.pvv.rolfn.tls.protocol.record.Finished;
import org.pvv.rolfn.tls.protocol.record.HandshakeMessage;
import org.pvv.rolfn.tls.protocol.record.HandshakeType;
import org.pvv.rolfn.tls.protocol.record.HandshakeVisitor;
import org.pvv.rolfn.tls.protocol.record.HelloRequest;
import org.pvv.rolfn.tls.protocol.record.ProtocolVersion;
import org.pvv.rolfn.tls.protocol.record.SecurityParameters;
import org.pvv.rolfn.tls.protocol.record.ServerHello;
import org.pvv.rolfn.tls.protocol.record.ServerHelloDone;
import org.pvv.rolfn.tls.protocol.record.ServerKeyExchange;
import org.pvv.rolfn.tls.protocol.record.TLSPlaintext;
import org.pvv.rolfn.tls.protocol.record.TLSRecord;
import org.pvv.rolfn.tls.protocol.record.TLSRecordProtocol;

public class TLSConnection {
	static private final Logger log = Logger.getLogger(TLSConnection.class);
	private SecurityParameters parameters;
	private TLSRecordProtocol tls;
	private HandshakeVisitor handshakeHandler;
	private byte[] sessionId;
	private List<ByteBuffer> handshakeMessages = new ArrayList<ByteBuffer>();
	
	public TLSConnection(ProtocolVersion version, ByteChannel channel) {
		this(version, channel, null);
	}
	
	public TLSConnection(ProtocolVersion version, ByteChannel channel, HandshakeVisitor handler) {
		parameters = new SecurityParameters();
		parameters.setProtocolVersion(version);
		if(handler == null) {
			handshakeHandler = new DefaultHandshakeHandler(this, parameters);
		} else {
			handshakeHandler = handler;
		}
		tls = new TLSRecordProtocol(channel, parameters);
	}
	
	/**
	 * Starts handshake. Only works if connection end is unset (implicit client) or set to client.
	 * @throws IOException
	 */
	public void init() throws IOException {
		if(parameters.getEntity() == ConnectionEnd.server) {
			throw new IOException("can only call init from client");
		}
		setConnectionEnd(ConnectionEnd.client);
		handshakeHandler.initiate();
		tls.commit();
	}

	public boolean isReady() {
		return handshakeHandler.isReadyToTransmitApplicationData();
	}

	public Prf getPrf() {
		return tls.getPrf();
	}

	public void setConnectionEnd(ConnectionEnd entity) {
		parameters.setEntity(entity);
	}
	
	public ByteBuffer readData() throws IOException {
		while(true) {
			TLSPlaintext record = tls.readMessage();
			if(record == null) {
				return null;
			}
			switch(record.getContentType()) {
			case application_data:
				return record.getData();
			case alert:
				// should have some configurable error-handling here...
				Alert a = Alert.read(record.getData());
				log.warn(a);
				throw new IOException(a.toString());
			case change_cipher_spec:
				changeCipherSpec();
				break;
			case handshake:
				
				readHandshake(record, parameters, handshakeHandler);
				// always commit here?
				tls.commit();
				break;
			}
		}
	}

	/**
	 * check if the given cipher suite is acceptable.
	 * @param cs cipher suite to test
	 * @return true if the given cipher suite is acceptable
	 */
	public boolean acceptCipherSuite(CipherSuite cs) {
		// TODO Auto-generated method stub
		return false;
	}

	/**
	 * change cipher spec as instructed by peer
	 */
	void changeCipherSpec() {
		log.debug("change cipher spec - read");
		// TODO change read state
	}
	
	/**
	 * Write changeCipherSpec message and change the state of the encrypt/verify engine to the
	 * appropriate one for the cipher suite in the current security params. 
	 */
	void writeChangeCipherSpec() {
		log.debug("change cipher spec - write");
		ByteBuffer buf = ByteBuffer.allocate(1);
		ChangeCipherSpec.change_cipher_spec.write(buf);
		buf.flip();
		tls.writeMessage(ContentType.change_cipher_spec, buf);
		// TODO change write state
	}

	public void writeMessage(HandshakeMessage hs) {
		ByteBuffer buf = ByteBuffer.allocate(hs.estimateSize()+4);
		hs.writeMessage(buf);
		if(!(hs instanceof HelloRequest)) {
			// save message for calculating hash in finished later
			// make sure the saved buffer is at the beginning, ready for reading
			handshakeMessages.add((ByteBuffer) buf.duplicate().rewind());
		}
		buf.flip();
		tls.writeMessage(ContentType.handshake, buf);
	}

	byte[] getSessionId() {
		return sessionId;
	}

	void setSessionId(byte[] sessionId) {
		this.sessionId = sessionId;
	}

	private void readHandshake(TLSRecord msg, SecurityParameters params, HandshakeVisitor v) {
		ByteBuffer buf = msg.getData();
		HandshakeMessage handshake;
		do {
			handshake = readHandshake(buf, params, v);
		} while(handshake != null);
	}

	public HandshakeMessage readHandshake(ByteBuffer buf, SecurityParameters params, HandshakeVisitor v) {
		if(buf.remaining() == 0) {
			return null;
		}
		if(buf.remaining() < 4) {
			throw new RuntimeException("missing data in handshake header, remaining="+buf.remaining());
		}
		// save start position
		buf.mark();
		
		byte msgTypeCode = buf.get();
		HandshakeType msgType = HandshakeType.byid(msgTypeCode);
		int length = ByteBufferUtils.getUnsigned24(buf);
		
		if(msgType == null) {
			log.warn("Received unknown handshake message: "+msgTypeCode);
			buf.position(buf.position()+length);
			throw new TLSException(AlertDescription.handshake_failure, AlertLevel.fatal);
		}
		
		log.debug("received: "+msgType.toString());
		
		// if not handshake instanceof HelloRequest => save last part of buf for Finished-message 
		if(msgType != HandshakeType.hello_request) {
			handshakeMessages.add(ByteBufferUtils.sliceMarkToLength(buf, length+4)); // +4 to include handshake header
		}
		
		switch(msgType) {
		case hello_request:	return visitAndReturn(HelloRequest.read(buf), v);
		case client_hello:	return visitAndReturn(ClientHello.read(buf, length), v);
		case server_hello:	return visitAndReturn(ServerHello.read(buf, length), v);
		case certificate: 	return visitAndReturn(Certificate.read(buf), v);
		case server_key_exchange: return visitAndReturn(ServerKeyExchange.read(buf, params), v);
		case certificate_request: return visitAndReturn(CertificateRequest.read(buf), v);
		case server_hello_done:   return visitAndReturn(ServerHelloDone.read(buf), v);
		case certificate_verify:  return visitAndReturn(CertificateVerify.read(buf), v);
		case client_key_exchange: return visitAndReturn(ClientKeyExchange.read(buf, params), v);
		case finished:            return visitAndReturn(Finished.read(buf, params), v);
		}
		// ending up here means we found a msgType known to the enum, but not mentioned in the switch
		// need something here of the compiler will complain...
		throw new IllegalStateException("unknown message type: "+msgType);
	}

	/**
	 * Iterate through all saved handshake-messages and compute hash.
	 * @return
	 */
	protected byte[] hashHandshakeMessages() {
		Prf prf = tls.getPrf();
		return prf.digest(handshakeMessages).array();
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
