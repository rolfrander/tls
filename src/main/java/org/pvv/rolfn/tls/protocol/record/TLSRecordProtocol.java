package org.pvv.rolfn.tls.protocol.record;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ByteChannel;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

/**
 * The TLS Record Protocol is a layered protocol. At each layer, messages may
 * include fields for length, description, and content. The Record Protocol
 * takes messages to be transmitted, fragments the data into manageable blocks,
 * optionally compresses the data, applies a MAC, encrypts, and transmits the
 * result. Received data is decrypted, verified, decompressed, reassembled, and
 * then delivered to higher-level clients.
 * 
 * @author RolfRander
 * @see http://tools.ietf.org/html/rfc5246#section-6
 * 
 */
public class TLSRecordProtocol {
	static private final Logger log = Logger.getLogger(TLSRecordProtocol.class);	
	static public final int TLS_MAX_RECORD_SIZE = 0x3fff;
	static public final int TLS_SAFEGUARD = 128;
	private int maxRecordSize = TLS_MAX_RECORD_SIZE - TLS_SAFEGUARD;
	private ByteChannel channel;
	private SecurityParameters params;
	private long seqCnt = 0;

	private Encryption encryption = NullEncryption.NULL;
	private Compression compression = NullCompression.NULL;

	private List<TLSPlaintext> pendingOutput;

	public TLSRecordProtocol(ByteChannel channel, SecurityParameters params) {
		this.channel = channel;
		this.params = params;
	}

	/**
	 * Reads a message, possibly only a fragment. Implements the read, decrypt,
	 * verify and decompress. Does not reassemble.
	 * 
	 * @return decoded record
	 * @throws IOException
	 */
	public TLSPlaintext readMessage() throws IOException {
		if(log.isDebugEnabled()) {
			log.debug("reading message seq="+seqCnt);
		}
		TLSCiphertext ciphertext = new TLSCiphertext();
		ByteBuffer buf = ByteBuffer.allocate(5);
		buf.order(ByteOrder.BIG_ENDIAN);
		switch(channel.read(buf)) {
		case 0:
			log.debug("no data read");
			return null;
		case 5:
			break;
		default:
			// what to do?
			// should save this and continue reading later, but not now...
			log.warn("incomplete TLS header");
			throw new IOException("broken TLS-header");
		}
		
		// the channel has written to the buffer, to start reading we need to flip...
		buf.flip();
		ciphertext.contentType = ContentType.read(buf);
		ciphertext.version = ProtocolVersion.read(buf);
		int length = buf.getShort();

		buf = ByteBuffer.allocate(length);
		while (buf.hasRemaining()) {
			if (channel.read(buf) == -1) {
				throw new EOFException("unexpected end-of-stream");
			}
		}

		ciphertext.data = buf.array();
		
		TLSCompressed compressed = encryption.decrypt(ciphertext);
		TLSPlaintext plaintext = compression.decompress(compressed);
		seqCnt++;
		return plaintext;
	}

	/**
	 * compress, add verification, encrypt and write.
	 * @param msg message to write
	 * @throws IOException 
	 */
	private void transformAndWrite(TLSPlaintext msg) throws IOException {
		log.debug("write message to channel");
		TLSCompressed compressed = compression.compress(msg);
		TLSCiphertext ciphertext = encryption.encrypt(compressed);
		
		// ensure that result is small enough
		if(ciphertext.getLength() > TLS_MAX_RECORD_SIZE) {
			log.error("message to large length="+ciphertext.getLength());
			throw new RuntimeException("encrypted length > TLS_MAX_RECORD_SIZE");
		}
		
		// construct output message
		ByteBuffer buf = ByteBuffer.allocate(5 + ciphertext.getLength());
		ciphertext.getContentType().write(buf);
		params.getProtocolVersion().write(buf);
		buf.putShort((short) ciphertext.getLength());
		buf.put(ciphertext.getData());
		buf.flip();
		channel.write(buf);
	}

	/**
	 * Prepares writing a message to output stream. Does not send any data until
	 * commit().
	 * 
	 * @param type
	 *            type of message to send
	 * @param data
	 *            data to send
	 */
	public void writeMessage(ContentType type, byte[] data) {
		if(log.isDebugEnabled()) {
			log.debug("write message type="+type);
		}
		if (type == null) {
			throw new NullPointerException("content type cannot be null");
		}
		if (data == null) {
			data = new byte[0];
		}
		if (pendingOutput == null) {
			pendingOutput = new ArrayList<TLSPlaintext>();
		}
		pendingOutput.add(new TLSPlaintext(type, data));
	}

	public void commit() throws IOException {
		log.debug("commit data to output channel");
		if (pendingOutput == null || pendingOutput.size() == 0) {
			// noop
			return;
		}

		List<TLSPlaintext> output = combinePendingOutput();

		splitAndWrite(output);
	}

	/**
	 * split oversized messages, then transform and write.
	 * 
	 * @param output list of messages to output
	 * @throws IOException 
	 */
	private void splitAndWrite(List<TLSPlaintext> output) throws IOException {
		for (TLSPlaintext msg : output) {
			if (msg.getLength() > maxRecordSize) {
				// split
				int startPos = 0;
				TLSPlaintext splitMsg = new TLSPlaintext(msg.getContentType(), null);
				while (startPos < msg.getLength()) {
					int l = Math.min(maxRecordSize, msg.getLength() - startPos);
					splitMsg.data = new byte[l];
					System.arraycopy(msg.data, startPos, splitMsg.data, 0, l);
					transformAndWrite(splitMsg);
					startPos += l;
				}
			} else {
				transformAndWrite(msg);
			}
		}
	}

	/**
	 * collect records with same content into one large record.
	 * 
	 * @return list of combined records
	 */
	private List<TLSPlaintext> combinePendingOutput() {
		List<TLSPlaintext> output = new ArrayList<TLSPlaintext>();
		int start = 0;
		ContentType currentType = pendingOutput.get(0).getContentType();
		int size = pendingOutput.get(0).getLength();
		// for all subsequent records with same type
		for (int i = 1; i < pendingOutput.size(); i++) {
			if (currentType != pendingOutput.get(i).getContentType()) {
				// combine
				output.add(combineMessages(start, i, size));
				start = i;
				size = 0;
				currentType = pendingOutput.get(i).getContentType();
			}
			size += pendingOutput.get(i).getLength();
		}
		// add rest of messages
		output.add(combineMessages(start, pendingOutput.size(), size));
		return output;
	}

	/**
	 * Combines messages in pending output queue between start and end.
	 * Including start, not including end.
	 * 
	 * @param start
	 *            first message to include
	 * @param end
	 *            message after last to include
	 * @param size
	 *            combined size of all payload in messages (size of buffer to
	 *            allocate)
	 * @return combined message
	 */
	private TLSPlaintext combineMessages(int start, int end, int size) {
		ContentType contentType = pendingOutput.get(start).getContentType();
		System.out.println("combining messages "+start+"-"+end+", total size "+size+", content type "+contentType);
		if (end - start == 1) {
			return pendingOutput.get(start);
		}
		ByteBuffer buf = ByteBuffer.allocate(size);
		for (int i = start; i < end; i++) {
			buf.put(pendingOutput.get(i).getData());
		}
		return new TLSPlaintext(contentType, buf.array());
	}

	public int getMaxRecordSize() {
		return maxRecordSize;
	}

	/**
	 * Adjust the max record size. This is just for testing purposes. TLS max
	 * record size is 2^14-1. It is bad form to have functionality in production
	 * code for testing, but what the heck...
	 * 
	 * @param maxRecordSize
	 */
	public void setMaxRecordSize(int maxRecordSize) {
		this.maxRecordSize = maxRecordSize;
	}
}
