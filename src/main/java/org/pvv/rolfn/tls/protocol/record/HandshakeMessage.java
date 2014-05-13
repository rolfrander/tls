package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.apache.log4j.Logger;
import org.pvv.rolfn.io.ByteBufferUtils;

abstract public class HandshakeMessage {
	static private final Logger log = Logger.getLogger(HandshakeMessage.class);
	
	protected void write(ByteBuffer buf) {
		throw new RuntimeException(this.getClass().getCanonicalName()+".write() not implemented");
	}
	
	public void writeMessage(ByteBuffer buf) {
		buf.put((byte) getMessageType().getId());
		ByteBufferUtils.putUnsigned24(buf, 0);
		write(buf);
		ByteBufferUtils.putUnsigned24(buf, 1, buf.limit()-4);
	}
	
	public int estimateSize() {
		throw new RuntimeException("not implemented");
	}
	
	abstract public HandshakeType getMessageType();
}
