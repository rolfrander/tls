package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

/**
 * 
 *   The change cipher spec protocol exists to signal transitions in
 *   ciphering strategies.  The protocol consists of a single message,
 *   which is encrypted and compressed under the current (not the pending)
 *   connection state.  The message consists of a single byte of value 1.
 *   The ChangeCipherSpec message is sent by both the client and the
 *   server to notify the receiving party that subsequent records will be
 *   protected under the newly negotiated CipherSpec and keys.  Reception
 *   of this message causes the receiver to instruct the record layer to
 *   immediately copy the read pending state into the read current state.
 *   Immediately after sending this message, the sender MUST instruct the
 *   record layer to make the write pending state the write active state.
 *   (See Section 6.1.)  The ChangeCipherSpec message is sent during the
 *   handshake after the security parameters have been agreed upon, but
 *   before the verifying Finished message is sent.
 *   
 * @author RolfRander
 * @see RFC 5246 section 7.1
 *
 */
public enum ChangeCipherSpec {
	change_cipher_spec(1);
	
	private int id;

	private ChangeCipherSpec(int id) {
		this.id = id;
	}
	
	static protected ChangeCipherSpec read(ByteBuffer buf) {
		byte id = buf.get();
		if(id == 1) { 
			return change_cipher_spec;
		}
		return null;
	}

	public void write(ByteBuffer buf) {
		buf.put((byte) id);
	}
}
