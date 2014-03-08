package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.util.*;

/**
 *  The TLS Handshake Protocol is one of the defined higher-level clients
 *  of the TLS Record Protocol.  This protocol is used to negotiate the
 *  secure attributes of a session.  Handshake messages are supplied to
 *  the TLS record layer, where they are encapsulated within one or more
 *  TLSPlaintext structures, which are processed and transmitted as
 *  specified by the current active session state.
 * @author RolfRander
 *
 */
public class Handshake extends Fragment {
	private List<HandshakeMessage> msg = new ArrayList<HandshakeMessage>();
	
	protected Handshake(ByteBuffer buf, SecurityParameters params)  {
		while(buf.hasRemaining()) {
			HandshakeType msgType = HandshakeType.byid(buf.get());
			int length = RecordUtils.getUnsigned24(buf);
			
			switch(msgType) {
			case hello_request:
				msg.add(new HelloRequest(buf));
				break;
			case client_hello:
				ClientHello clientHello = new ClientHello(buf, length);
				params.setClientRandom(clientHello.getRandom());
				msg.add(clientHello);
				break;
			case server_hello:
				ServerHello serverHello = new ServerHello(buf, length);
				params.setCipherSuite(serverHello.getCipherSuite());
				params.setServerRandom(serverHello.getRandom());
				msg.add(serverHello);
				break;
			case certificate: 
				// is this a server-certificate or a client certificate?
				// am I a server or a client?
				Certificate certificate = new Certificate(buf);
				switch(params.getEntity()) {
				case client:
					params.setServerCertificate(certificate);
					break;
				case server:
					params.setClientCertificate(certificate);
					break;
				}
				msg.add(certificate);
				break;
			case server_key_exchange:
				msg.add(new ServerKeyExchange(buf, params));
				break;
			case certificate_request:
				msg.add(new CertificateRequest(buf));
				break;
			case server_hello_done:
				msg.add(new ServerHelloDone(buf));
				break;
			case certificate_verify:
				msg.add(new CertificateVerify(buf));
				break;
			case client_key_exchange:
				msg.add(new ClientKeyExchange(buf, params));
				break;
			case finished:
				msg.add(new Finished(buf));
				break;
			}
		}
	}
}
