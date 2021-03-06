package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

/**
 * A Finished message is always sent immediately after a change cipher spec
 * message to verify that the key exchange and authentication processes were
 * successful. It is essential that a change cipher spec message be received
 * between the other handshake messages and the Finished message.
 * 
 * @author RolfRander
 * @see http://tools.ietf.org/html/rfc5246#section-7.4.9
 * 
 */
public class Finished extends HandshakeMessage {

	public static final String FINISHED_LABEL_CLIENT = "client finished";
	public static final String FINISHED_LABEL_SERVER = "server finished";

	private byte[] verifyData;

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.finished;
	}

	public Finished(byte[] verifyData) {
		this.verifyData = verifyData;
	}

	public static Finished read(ByteBuffer buf, SecurityParameters params) {
		int verifyDataLength = params.getVerifyDataLength();
		byte[] verifyData = new byte[verifyDataLength];
		buf.get(verifyData);
		return new Finished(verifyData);
	}

	public byte[] getVerifyData() {
		return verifyData;
	}

	@Override
	protected void write(ByteBuffer buf) {
		buf.put(verifyData);
	}

	@Override
	public int estimateSize() {
		return verifyData.length;
	}
}
