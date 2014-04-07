package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

/**
 * The HelloRequest message MAY be sent by the server at any time.
 * 
 * HelloRequest is a simple notification that the client should begin the
 * negotiation process anew. In response, the client should send a ClientHello
 * message when convenient. This message is not intended to establish which side
 * is the client or server but merely to initiate a new negotiation. Servers
 * SHOULD NOT send a HelloRequest immediately upon the client's initial
 * connection. It is the client's job to send a ClientHello at that time.
 * 
 * This message will be ignored by the client if the client is currently
 * negotiating a session. This message MAY be ignored by the client if it does
 * not wish to renegotiate a session, or the client may, if it wishes, respond
 * with a no_renegotiation alert. Since handshake messages are intended to have
 * transmission precedence over application data, it is expected that the
 * negotiation will begin before no more than a few records are received from
 * the client. If the server sends a HelloRequest but does not receive a
 * ClientHello in response, it may close the connection with a fatal alert.
 * 
 * After sending a HelloRequest, servers SHOULD NOT repeat the request until the
 * subsequent handshake negotiation is complete.
 * 
 * @author RolfRander
 * 
 */
public class HelloRequest extends HandshakeMessage {

	public HelloRequest() {
		// Empty
	}

	static protected HelloRequest read(ByteBuffer buf) {
		return new HelloRequest();
	}
}
