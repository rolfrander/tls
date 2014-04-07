package org.pvv.rolfn.tls.protocol.record;

public interface HandshakeVisitor {

	/**
	 * The HelloRequest message MAY be sent by the server at any time.
	 * 
	 * @see http://tools.ietf.org/html/rfc5246#section-7.4.1.1
	 * @param hello
	 */
	void helloRequest(HelloRequest hello);

	/**
	 * When a client first connects to a server, it is required to send the
	 * ClientHello as its first message. The client can also send a ClientHello
	 * in response to a HelloRequest or on its own initiative in order to
	 * renegotiate the security parameters in an existing connection.
	 * 
	 * @param clientHello
	 * @see http://tools.ietf.org/html/rfc5246#section-7.4.1.2
	 */
	void clientHello(ClientHello clientHello);

	/**
	 * The server will send this message in response to a ClientHello message
	 * when it was able to find an acceptable set of algorithms. If it cannot
	 * find such a match, it will respond with a handshake failure alert.
	 * 
	 * @see http://tools.ietf.org/html/rfc5246#section-7.4.1.3
	 * @param srvHello
	 */
	void serverHello(ServerHello srvHello);

	/**
	 * Server or client certificate. The server MUST send a Certificate message
	 * whenever the agreed- upon key exchange method uses certificates for
	 * authentication (this includes all key exchange methods defined in this
	 * document except DH_anon). This message will always immediately follow the
	 * ServerHello message.
	 * <p>
	 * Client certificate: This is the first message the client can send after
	 * receiving a ServerHelloDone message. This message is only sent if the
	 * server requests a certificate. If no suitable certificate is available,
	 * the client MUST send a certificate message containing no certificates.
	 * That is, the certificate_list structure has a length of zero. If the
	 * client does not send any certificates, the server MAY at its discretion
	 * either continue the handshake without client authentication, or respond
	 * with a fatal handshake_failure alert. Also, if some aspect of the
	 * certificate chain was unacceptable (e.g., it was not signed by a known,
	 * trusted CA), the server MAY at its discretion either continue the
	 * handshake (considering the client unauthenticated) or send a fatal alert.
	 * 
	 * @param cert
	 * @see http://tools.ietf.org/html/rfc5246#section-7.4.2
	 * 
	 */
	void certificate(Certificate cert);

	/**
	 * This message will be sent immediately after the server Certificate
	 * message (or the ServerHello message, if this is an anonymous
	 * negotiation).
	 * 
	 * @param serverKeyExchange
	 * @see http://tools.ietf.org/html/rfc5246#section-7.4.3
	 */
	void serverKeyExchange(ServerKeyExchange serverKeyExchange);

	/**
	 * A non-anonymous server can optionally request a certificate from the
	 * client, if appropriate for the selected cipher suite. This message, if
	 * sent, will immediately follow the ServerKeyExchange message (if it is
	 * sent; otherwise, this message follows the server's Certificate message).
	 * 
	 * @param certReq
	 * @see http://tools.ietf.org/html/rfc5246#section-7.4.4
	 */
	void certificateRequest(CertificateRequest certReq);

	/**
	 * The ServerHelloDone message is sent by the server to indicate the end of
	 * the ServerHello and associated messages. After sending this message, the
	 * server will wait for a client response.
	 * 
	 * @param serverHelloDone
	 * @see http://tools.ietf.org/html/rfc5246#section-7.4.5
	 */
	void serverHelloDone(ServerHelloDone serverHelloDone);

	/**
	 * This message is always sent by the client. It MUST immediately follow the
	 * client certificate message, if it is sent. Otherwise, it MUST be the
	 * first message sent by the client after it receives the ServerHelloDone
	 * message.
	 * 
	 * @param clientKeyExchange
	 * @see http://tools.ietf.org/html/rfc5246#section-7.4.7
	 */
	void clientKeyExchange(ClientKeyExchange clientKeyExchange);

	/**
	 * This message is used to provide explicit verification of a client
	 * certificate. This message is only sent following a client certificate
	 * that has signing capability (i.e., all certificates except those
	 * containing fixed Diffie-Hellman parameters). When sent, it MUST
	 * immediately follow the client key exchange message.
	 * 
	 * @param certificateVerify
	 * @see http://tools.ietf.org/html/rfc5246#section-7.4.8
	 */
	void certificateVerify(CertificateVerify certificateVerify);

	/**
	 * A Finished message is always sent immediately after a change cipher spec
	 * message to verify that the key exchange and authentication processes were
	 * successful. It is essential that a change cipher spec message be received
	 * between the other handshake messages and the Finished message.
	 * 
	 * @param finished
	 * @see http://tools.ietf.org/html/rfc5246#section-7.4.9
	 */
	void finished(Finished finished);

	boolean isReadyToTransmitApplicationData();

}
