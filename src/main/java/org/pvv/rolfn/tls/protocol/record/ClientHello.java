package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.util.*;

import org.pvv.rolfn.io.ByteBufferUtils;

/**
 * When a client first connects to a server, it is required to send the
 * ClientHello as its first message. The client can also send a ClientHello in
 * response to a HelloRequest or on its own initiative in order to renegotiate
 * the security parameters in an existing connection.
 * 
 * @author RolfRander
 * 
 */
public class ClientHello extends HandshakeMessage {

	/**
	 * The version of the TLS protocol by which the client wishes to communicate
	 * during this session. This SHOULD be the latest (highest valued) version
	 * supported by the client. For this version of the specification, the
	 * version will be 3.3 (see Appendix E for details about backward
	 * compatibility).
	 */
	private ProtocolVersion clientVersion;

	/**
	 * A client-generated random structure.
	 */
	private TLSRandom random;

	/**
	 * The ID of a session the client wishes to use for this connection. This
	 * field is empty if no session_id is available, or if the client wishes to
	 * generate new security parameters.
	 */
	byte sessionId[];

	/**
	 * This is a list of the cryptographic options supported by the client, with
	 * the client's first preference first. If the session_id field is not empty
	 * (implying a session resumption request), this vector MUST include at
	 * least the cipher_suite from that session. Values are defined in Appendix
	 * A.5.
	 */
	List<CipherSuite> cipherSuites = new ArrayList<CipherSuite>();

	/**
	 * This is a list of the compression methods supported by the client, sorted
	 * by client preference. If the session_id field is not empty (implying a
	 * session resumption request), it MUST include the compression_method from
	 * that session. This vector MUST contain, and all implementations MUST
	 * support, CompressionMethod.null. Thus, a client and server will always be
	 * able to agree on a compression method.
	 */
	byte compressionMethods[];

	/**
	 * Clients MAY request extended functionality from servers by sending data
	 * in the extensions field. The actual "Extension" format is defined in
	 * Section 7.4.1.4.
	 */
	byte extensions[];

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.client_hello;
	}

	public ClientHello(ProtocolVersion version, Random rnd) {
		clientVersion = version;
		random = new TLSRandom(rnd);
		compressionMethods = new byte[1];
		compressionMethods[0] = (byte)0;
		extensions = new byte[0];
	}
	
	public void addCipherSuite(CipherSuite cs) {
		cipherSuites.add(cs);
	}	
	
	private ClientHello(ByteBuffer buf, int len) {
		int start = buf.position();
		clientVersion = ProtocolVersion.read(buf);
		random = TLSRandom.read(buf);
		sessionId = ByteBufferUtils.readArray8(buf);
		int cipherSuitesLen = ByteBufferUtils.getUnsignedShort(buf);
		for (int i = 0; i < cipherSuitesLen; i += 2) {
			cipherSuites.add(CipherSuite.read(buf));
		}
		compressionMethods = ByteBufferUtils.readArray8(buf);
		if (buf.position() < (start + len)) {
			// extensions_present
			extensions = ByteBufferUtils.readArray16(buf);
		}
	}

	public static ClientHello read(ByteBuffer buf, int len) {
		return new ClientHello(buf, len);
	}
	
	@Override
	protected void write(ByteBuffer buf) {
		clientVersion.write(buf);
		random.write(buf);
		if(sessionId == null) {
			buf.put((byte)0);
		} else {
			ByteBufferUtils.writeArray8(buf, sessionId);
		}
		buf.putShort((short) (cipherSuites.size() * CipherSuite.octets()));
		for(CipherSuite cs: cipherSuites) {
			cs.write(buf);
		}
		ByteBufferUtils.writeArray8(buf, compressionMethods);
		if(extensions != null) {
			ByteBufferUtils.writeArray16(buf, extensions);
		}
	}
	
	public int estimateSize() {
		int size = 0;
		size += 2; // client version
		size += 32; // random
		if(sessionId == null) {
			size += 1;
		} else {
			size += 1+sessionId.length;
		}
		size += 2 + cipherSuites.size() * CipherSuite.octets();
		size += 1 + compressionMethods.length;
		if(extensions != null) {
			size += 2 + extensions.length;
		}
		return size;
	}
	
	public ProtocolVersion getClientVersion() {
		return clientVersion;
	}

	public TLSRandom getRandom() {
		return random;
	}

	public byte[] getSessionId() {
		return sessionId;
	}

	public List<CipherSuite> getCipherSuites() {
		return Collections.unmodifiableList(cipherSuites);
	}

	public byte[] getCompressionMethods() {
		return compressionMethods;
	}

}
