package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.apache.log4j.Logger;
import org.pvv.rolfn.io.ByteBufferUtils;

public class HandshakeMessage {
	static private final Logger log = Logger.getLogger(HandshakeMessage.class);
	
	protected void write(ByteBuffer buf) {
		throw new RuntimeException(this.getClass().getCanonicalName()+".write() not implemented");
	}
	
	public void writeMessage(ByteBuffer buf) {
		if(this instanceof ClientHello) {
			buf.put((byte) HandshakeType.client_hello.getId());
		}
		ByteBufferUtils.putUnsigned24(buf, 0);
		write(buf);
		buf.position(1);
		ByteBufferUtils.putUnsigned24(buf, buf.limit()-4);		
	}
	
	public int estimateSize() {
		throw new RuntimeException("not implemented");
	}
}
