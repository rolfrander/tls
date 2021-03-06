package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

/**
 * The server will send this message in response to a ClientHello message when
 * it was able to find an acceptable set of algorithms. If it cannot find such a
 * match, it will respond with a handshake failure alert.
 * 
 * @author RolfRander
 * 
 */
public class ServerHello extends HandshakeMessage {

	/**
	 * This field will contain the lower of that suggested by the client in the
	 * client hello and the highest supported by the server. For this version of
	 * the specification, the version is 3.3. (See Appendix E for details about
	 * backward compatibility.)
	 */
	private ProtocolVersion serverVersion;

	/**
	 * This structure is generated by the server and MUST be independently
	 * generated from the ClientHello.random.
	 */
	private TLSRandom random;

	/**
	 * This is the identity of the session corresponding to this connection. If
	 * the ClientHello.session_id was non-empty, the server will look in its
	 * session cache for a match. If a match is found and the server is willing
	 * to establish the new connection using the specified session state, the
	 * server will respond with the same value as was supplied by the client.
	 * This indicates a resumed session and dictates that the parties must
	 * proceed directly to the Finished messages. Otherwise, this field will
	 * contain a different value identifying the new session. The server may
	 * return an empty session_id to indicate that the session will not be
	 * cached and therefore cannot be resumed. If a session is resumed, it must
	 * be resumed using the same cipher suite it was originally negotiated with.
	 * Note that there is no requirement that the server resume any session even
	 * if it had formerly provided a session_id. Clients MUST be prepared to do
	 * a full negotiation -- including negotiating new cipher suites -- during
	 * any handshake.
	 */
	private byte sessionId[];

	/**
	 * The single cipher suite selected by the server from the list in
	 * ClientHello.cipher_suites. For resumed sessions, this field is the value
	 * from the state of the session being resumed.
	 */
	private CipherSuite cipherSuite;

	/**
	 * The single compression algorithm selected by the server from the list in
	 * ClientHello.compression_methods. For resumed sessions, this field is the
	 * value from the resumed session state.
	 */
	private byte compressionMethod;

	/**
	 * A list of extensions. Note that only extensions offered by the client can
	 * appear in the server's list.
	 * TODO extensions are not implemented yet
	 */
	private byte extensions[];

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.server_hello;
	}

	private ServerHello() {
		
	}
	
	public static ServerHello read(ByteBuffer buf, int len) {
		ServerHello sh = new ServerHello();
		int start = buf.position();
		sh.serverVersion = ProtocolVersion.read(buf);
		sh.random = TLSRandom.read(buf);
		sh.sessionId = ByteBufferUtils.readArray8(buf);
		sh.cipherSuite = CipherSuite.read(buf);
		sh.compressionMethod = buf.get();
		if (buf.position() < start + len) {
			// extensions present
			sh.extensions = ByteBufferUtils.readArray16(buf);
		}
		return sh;
	}

	public ProtocolVersion getServerVersion() {
		return serverVersion;
	}

	public TLSRandom getRandom() {
		return random;
	}

	public byte[] getSessionId() {
		return sessionId;
	}

	public CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	public byte getCompressionMethod() {
		return compressionMethod;
	}

}
