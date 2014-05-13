package org.pvv.rolfn.tls.protocol;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

import org.apache.log4j.Logger;
import org.pvv.rolfn.io.ByteBufferUtils;
import org.pvv.rolfn.tls.crypto.DiffieHellman;
import org.pvv.rolfn.tls.protocol.record.AlertDescription;
import org.pvv.rolfn.tls.protocol.record.AlertLevel;
import org.pvv.rolfn.tls.protocol.record.Certificate;
import org.pvv.rolfn.tls.protocol.record.CertificateRequest;
import org.pvv.rolfn.tls.protocol.record.CertificateVerify;
import org.pvv.rolfn.tls.protocol.record.CipherSuite;
import org.pvv.rolfn.tls.protocol.record.ClientDiffieHellmanPublic;
import org.pvv.rolfn.tls.protocol.record.ClientHello;
import org.pvv.rolfn.tls.protocol.record.ClientKeyExchange;
import org.pvv.rolfn.tls.protocol.record.ClientKeyExchangeTest;
import org.pvv.rolfn.tls.protocol.record.ConnectionEnd;
import org.pvv.rolfn.tls.protocol.record.Finished;
import org.pvv.rolfn.tls.protocol.record.HandshakeType;
import org.pvv.rolfn.tls.protocol.record.HandshakeVisitor;
import org.pvv.rolfn.tls.protocol.record.HelloRequest;
import org.pvv.rolfn.tls.protocol.record.ProtocolVersion;
import org.pvv.rolfn.tls.protocol.record.SecurityParameters;
import org.pvv.rolfn.tls.protocol.record.ServerDHParams;
import org.pvv.rolfn.tls.protocol.record.ServerHello;
import org.pvv.rolfn.tls.protocol.record.ServerHelloDone;
import org.pvv.rolfn.tls.protocol.record.ServerKeyExchange;

/**
 * Handling the handshake protocol.
 * A TLSException may be thrown at any time if anything unexpected occurs.
 * <pre>
 *     Client                                               Server
 *
 *     ClientHello                  -------->
 *                                                     ServerHello
 *                                                    Certificate*
 *                                              ServerKeyExchange*
 *                                             CertificateRequest*
 *                                  <--------      ServerHelloDone
 *     Certificate*
 *     ClientKeyExchange
 *     CertificateVerify*
 *     [ChangeCipherSpec]
 *     Finished                     -------->
 *                                              [ChangeCipherSpec]
 *                                  <--------             Finished
 *     Application Data             <------->     Application Data
 * </pre>
 * 
 * @author RolfRander
 * @see TLSException
 */
public class DefaultHandshakeHandler implements HandshakeVisitor {
	static private final Logger log = Logger.getLogger(DefaultHandshakeHandler.class);
	private static final byte[] MASTER_SECRET_LABEL = new byte[]{
		(byte)109, (byte)97, (byte)115, (byte)116, (byte)101, (byte)114, (byte)32, // master <space> 
		(byte)115, (byte)101, (byte)99, (byte)114, (byte)101, (byte)116};          // secret
	private static final int MASTER_SECRET_LENGTH = 48;
	
	static private enum HandshakeState {
		clean, negotiating, handshakeDone
	};
	
	private HandshakeState state = HandshakeState.clean;
	private SecurityParameters params;
	private TLSConnection connection;
	private SecureRandom random;
	private BitSet acceptedMessages = new BitSet(HandshakeType.maxId());
	private CertificateRequest certReq;
	private ClientKeyExchange cke;
	
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

	
	/*
	 * General API for protocol state-machine:
	 * - at the end of each message-handling method, define a list of 
	 *   expected next-messages by calling expect(HandshakeType...)
	 * - at the beginning of each message-handling method, check that the
	 *   received message is amongst the accepted by calling accept(HandshakeType)
	 *   
	 * accept() throws an exception if an unexpected message is received, and clears
	 * the list of accepted messages when returning
	 */
	
	final private void accept(HandshakeType msg) {
		int msgId = msg.getId();
		if(acceptedMessages.get(msgId)) {
			acceptedMessages.clear();
		} else {
			StringBuilder sb = new StringBuilder();
			sb.append("expected one of (");
			boolean first = true;
			for(int i=acceptedMessages.nextSetBit(0); i >= 0; i=acceptedMessages.nextSetBit(i+1)) {
				if(!first) {
					sb.append(", ");
				}
				first = false;
				sb.append(HandshakeType.byid(i).toString());
			}
			sb.append("), got: ");
			sb.append(msg.toString());
			unexpectedMessage(sb.toString());
		}
	}
	
	final private void expect(HandshakeType... expected) {
		acceptedMessages.clear();
		for(HandshakeType h: expected) {
			acceptedMessages.set(h.getId());
		}
	}
	
	final private boolean isServer() {
		return params.getEntity() == ConnectionEnd.server;
	}

	final private boolean isClient() {
		return params.getEntity() == ConnectionEnd.client;
	}
	
	private void unexpectedMessage(String msg) throws TLSException {
		log.error(msg);
		throw new TLSException(AlertDescription.unexpected_message, AlertLevel.fatal);
	}

	@Override
	public boolean isReadyToTransmitApplicationData() {
		return state == HandshakeState.handshakeDone;
	}
	

	/**
	 * initiate a connection from the client
	 */
	@Override
	public void initiate() {
		if(isServer()) {
			throw new RuntimeException("server cannot initiate a new connection");
		}
		// if entity is not set, it shall be client
		params.setEntity(ConnectionEnd.client);
		
		ClientHello clientHello = new ClientHello(params.getProtocolVersion(), random);
		params.setClientRandom(clientHello.getRandom());
		clientHello.addCipherSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
		clientHello.addCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
		clientHello.addCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
		
		// TODO: session id?
		connection.writeMessage(clientHello);
		expect(HandshakeType.server_hello);
	}
	
	@Override
	public void helloRequest(HelloRequest hello) {
		// ignore helloRequest if in the middle of negotiation
		if(state == HandshakeState.negotiating) {
			log.info("HelloRequest received while already negotiating");
			return;
		}
		state = HandshakeState.negotiating;
		if(isClient()) {
			initiate();
		} else {
			// isServer...
			expect(HandshakeType.client_hello);
		}
	}

	@Override
	public void clientHello(ClientHello clientHello) {
		if(state == HandshakeState.negotiating) {
			accept(HandshakeType.client_hello);
		} else {
			if(!isServer()) {
				unexpectedMessage("only server can accept client hello");
			}
			// implicit renegotiate
			// TODO: accept renegotiate?
			state = HandshakeState.negotiating;
		}
		
		params.setProtocolVersion(selectProtocolVersion(clientHello.getClientVersion()));
		params.setClientRandom(clientHello.getRandom());
		// TODO: session resume
		connection.setSessionId(clientHello.getSessionId());
		params.setCipherSuite(selectCipherSuite(clientHello.getCipherSuites()));
		// TODO: compression methods?
		params.setCompressionAlgorithm((short) 0);
		// TODO: extensions?
		
		// TODO serverHello
		
		// TODO certificate
		
		// TODO serverKeyExchange
		
		// TODO certificateRequest
		
		// TODO serverHelloDone
		
		// if(certificateRequest is sent)
		// expect(HandshakeType.certificate);
		// else
		// expect(HandshakeType.client_key_exchange);
	}



	@Override
	public void serverHello(ServerHello srvHello) {
		accept(HandshakeType.server_hello);
		// TODO: should do some sanity checking here
		params.setProtocolVersion(srvHello.getServerVersion());
		params.setServerRandom(srvHello.getRandom());
		params.setCipherSuite(srvHello.getCipherSuite());
		connection.setSessionId(srvHello.getSessionId());
		// TODO: compression methods?
		params.setCompressionAlgorithm((short)0);
		// TODO: extensions?
		
		nextMessageFromServerAfter(HandshakeType.server_hello);
	}

	@Override
	public void certificate(Certificate cert) {
		accept(HandshakeType.certificate);
		switch(params.getEntity()) {
		case client:
			params.setServerCertificate(cert);
			nextMessageFromServerAfter(HandshakeType.certificate);
			break;
		case server:
			params.setClientCertificate(cert);
			expect(HandshakeType.client_key_exchange);
			break;
		}
		// TODO: check certificate validity
		// TODO: crosscheck certificate type and ciphersuite key exchange alg
	}

	@Override
	public void serverKeyExchange(ServerKeyExchange ske) {
		accept(HandshakeType.server_key_exchange);

		if(ske.getDhParams() != null) {
			try {
				// TODO save this, need secret key later on
				DiffieHellman dh = new DiffieHellman();
				dh.setServerParams(ske.getDhParams());
				cke = new ClientKeyExchange(new ClientDiffieHellmanPublic(dh.getClientKey()));
				setMasterSecret(dh.getSharedSecret());
			} catch (Exception e) {
				// TODO: handle exception
				log.error("error creating DH-parameters", e);
				throw new TLSException(AlertDescription.handshake_failure, AlertLevel.fatal);
			}
		} else if(ske.getEcdhParams() != null) {
			log.error("ecdh not implemented");
			throw new TLSException(AlertDescription.handshake_failure, AlertLevel.fatal);
		} else {
			log.error("unknown parameters in server key exchange");
			throw new TLSException(AlertDescription.handshake_failure, AlertLevel.fatal);
		}

		// TODO check signature
		
		nextMessageFromServerAfter(HandshakeType.server_key_exchange);
	}

	/**
	 * Generates master secret from the pre-master secret.
	 * @ref http://tools.ietf.org/html/rfc5246#section-8.1
	 * @param preMasterSecret
	 */
	private void setMasterSecret(byte[] preMasterSecret) {
		if(params.getMasterSecret() != null) {
			log.warn("master secret set twice");
		}
		byte[] masterSecret = new byte[MASTER_SECRET_LENGTH];
		byte[] clientRandom = params.getClientRandom().getData();
		byte[] serverRandom = params.getServerRandom().getData();
		byte[] seed = ByteBufferUtils.concat(clientRandom, serverRandom);
		connection.getPrf().prf(preMasterSecret, MASTER_SECRET_LABEL, seed, MASTER_SECRET_LENGTH).get(masterSecret);
		params.setMasterSecret(masterSecret);
	}


	private void nextMessageFromServerAfter(HandshakeType ht) {
		switch(ht) {
		case server_hello:
			if(params.getKeyExchange().needCert()) {
				expect(HandshakeType.certificate); 
				break ;
			}
			// fallthrough
		case certificate:
			if(params.getKeyExchange().needServerKeyExchange()) {
				expect(HandshakeType.server_key_exchange); 
				break ;
			}
			// fallthrough
		case server_key_exchange:
			expect(HandshakeType.certificate_request, HandshakeType.server_hello_done);
			break;
			
		default:
			throw new RuntimeException("nextMessageFromServer called with unsupported handshake type: "+ht);
		}
	}
	
	@Override
	public void certificateRequest(CertificateRequest certReq) {
		accept(HandshakeType.certificate_request);
		this.certReq = certReq;
		expect(HandshakeType.server_hello_done);
	}

	@Override
	public void clientKeyExchange(ClientKeyExchange clientKeyExchange) {
		accept(HandshakeType.client_key_exchange);

		// TODO Auto-generated method stub
		// if client has sent certificate
		expect(HandshakeType.certificate_verify);
		// else
		expect(HandshakeType.finished);
	}

	@Override
	public void serverHelloDone(ServerHelloDone serverHelloDone) {
		accept(HandshakeType.server_hello_done);

		if(this.certReq != null) {
			// TODO where to get the certificate?
			Certificate certificate = new Certificate(null);
			connection.writeMessage(certificate);
		}
		
		// TODO send client key exchange
		if(this.cke != null) {
			connection.writeMessage(this.cke);
		} else {
			// TODO generate cke with encrypted pre_master_secret...
		}
		
		if(this.certReq != null) {
			// if client has sent certificate
			// TODO send certificate verify
		}
		
		connection.writeChangeCipherSpec();
		
		Finished finished = new Finished(computeVerifyData(ConnectionEnd.client));
		connection.writeMessage(finished);
		
		expect(HandshakeType.finished);
	}

	@Override
	public void certificateVerify(CertificateVerify certificateVerify) {
		accept(HandshakeType.certificate_verify);
		// TODO Auto-generated method stub
		
		expect(HandshakeType.finished);
	}

	@Override
	public void finished(Finished finished) {
		accept(HandshakeType.finished);
		byte verifyData[];
		
		if(isServer()) {
			connection.changeCipherSpec();
			verifyData = computeVerifyData(ConnectionEnd.client);
			Finished serverFinished = new Finished(computeVerifyData(ConnectionEnd.server));
			connection.writeMessage(serverFinished);
		} else {
			verifyData = computeVerifyData(ConnectionEnd.server);			
		}

		if(!Arrays.equals(verifyData, finished.getVerifyData())) {
			log.error("verification of finished-message failed");
			throw new TLSException(AlertDescription.handshake_failure, AlertLevel.fatal);
		}
		
		state = HandshakeState.handshakeDone;
	}

	private byte[] computeVerifyData(ConnectionEnd end) {
		int len = params.getVerifyDataLength();
		byte[] verifyData = new byte[len];
		byte[] handshakeMsgHash = connection.hashHandshakeMessages();
		ByteBuffer ret = connection.getPrf().prf(params.getMasterSecret(), getFinishedLabel(end), handshakeMsgHash, len);
		ret.get(verifyData);
		return verifyData;
	}

	private byte[] getFinishedLabel(ConnectionEnd end) {
		try {
			return (end == ConnectionEnd.client ? Finished.FINISHED_LABEL_CLIENT 
												: Finished.FINISHED_LABEL_SERVER)
				   .getBytes("ASCII");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Selects a cipher suite from a list of alternatives.
	 * @param cipherSuites
	 * @return the first cipher suite in the list that is acceptable to the TLSConnection
	 * @see TLSConnection#acceptCipherSuite(CipherSuite)
	 */
	protected CipherSuite selectCipherSuite(List<CipherSuite> cipherSuites) {
		for(CipherSuite cs: cipherSuites) {
			if(connection.acceptCipherSuite(cs)) {
				return cs;
			}
		}
		throw new TLSException(AlertDescription.handshake_failure, AlertLevel.fatal);
	}

	/**
	 * Select TLS-version less than or equal to the given client version.
	 * Returns null if none of these versions are supported.
	 * @param clientVersion
	 * @return the lowest version of 1.2 and the one suggested by the client
	 */
	private ProtocolVersion selectProtocolVersion(ProtocolVersion clientVersion) {
		if(ProtocolVersion.TLS1_2.compareTo(clientVersion) < 0) {
			return ProtocolVersion.TLS1_2;
		} else {
			return clientVersion;
		}
	}
}
