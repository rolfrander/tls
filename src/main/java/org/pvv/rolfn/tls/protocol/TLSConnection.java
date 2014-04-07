package org.pvv.rolfn.tls.protocol;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;

import org.apache.log4j.Logger;
import org.pvv.rolfn.tls.protocol.record.Alert;
import org.pvv.rolfn.tls.protocol.record.Certificate;
import org.pvv.rolfn.tls.protocol.record.CertificateRequest;
import org.pvv.rolfn.tls.protocol.record.CertificateVerify;
import org.pvv.rolfn.tls.protocol.record.ClientHello;
import org.pvv.rolfn.tls.protocol.record.ClientKeyExchange;
import org.pvv.rolfn.tls.protocol.record.ConnectionEnd;
import org.pvv.rolfn.tls.protocol.record.ContentType;
import org.pvv.rolfn.tls.protocol.record.Finished;
import org.pvv.rolfn.tls.protocol.record.HandshakeMessage;
import org.pvv.rolfn.tls.protocol.record.HandshakeVisitor;
import org.pvv.rolfn.tls.protocol.record.HelloRequest;
import org.pvv.rolfn.tls.protocol.record.SecurityParameters;
import org.pvv.rolfn.tls.protocol.record.ServerHello;
import org.pvv.rolfn.tls.protocol.record.ServerHelloDone;
import org.pvv.rolfn.tls.protocol.record.ServerKeyExchange;
import org.pvv.rolfn.tls.protocol.record.TLSPlaintext;
import org.pvv.rolfn.tls.protocol.record.TLSRecordProtocol;

public class TLSConnection {
	static private final Logger log = Logger.getLogger(TLSConnection.class);
	private SecurityParameters parameters;
	private TLSRecordProtocol tls;
	private HandshakeVisitor handshakeHandler;
	
	public TLSConnection(ByteChannel channel, HandshakeVisitor handler) {
		parameters = new SecurityParameters();
		handshakeHandler = handler;
		tls = new TLSRecordProtocol(channel, parameters);
	}
	
	public void setConnectionEnd(ConnectionEnd entity) {
		parameters.setEntity(entity);
	}
	
	public byte[] readData() throws IOException {
		while(true) {
			TLSPlaintext record = tls.readMessage();
			switch(record.getContentType()) {
			case application_data:
				return record.getData();
			case alert:
				// should have some configurable error-handling here...
				Alert a = Alert.read(record);
				log.warn(a);
				throw new IOException(a.toString());
			case change_cipher_spec:
				changeCipherSpec();
				break;
			case handshake:
				HandshakeMessage.read(record, parameters, handshakeHandler);
				// allways commit here?
				tls.commit();
				break;
			}
		}
	}

	private void changeCipherSpec() {
		// TODO Auto-generated method stub
		
	}

	public void writeMessage(HandshakeMessage hs) {
		ByteBuffer buf = ByteBuffer.allocate(hs.estimateSize());
		hs.write(buf);
		tls.writeMessage(ContentType.handshake, buf.array());
	}
}
