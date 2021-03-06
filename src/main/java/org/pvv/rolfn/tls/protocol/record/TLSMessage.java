package org.pvv.rolfn.tls.protocol.record;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;

public class TLSMessage {
	private ContentType contentType;
	private ProtocolVersion version;
	private short length; // egentlig uint16, men kun 14 bits brukes til lengde
	
	protected TLSMessage(ReadableByteChannel in, SecurityParameters params) throws IOException {
		ByteBuffer buf = ByteBuffer.allocate(5);
		buf.order(ByteOrder.BIG_ENDIAN);
		in.read(buf);
		this.contentType = ContentType.read(buf);
		this.version = ProtocolVersion.read(buf);
		this.length = buf.getShort();
		
		buf = ByteBuffer.allocate(length);
		in.read(buf);
	}

	public ContentType getContentType() {
		return contentType;
	}

	public ProtocolVersion getVersion() {
		return version;
	}

	public short getLength() {
		return length;
	}
	
}
