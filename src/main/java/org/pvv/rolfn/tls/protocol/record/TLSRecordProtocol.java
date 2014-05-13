package org.pvv.rolfn.tls.protocol.record;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ByteChannel;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.pvv.rolfn.io.ByteBufferUtils;
import org.pvv.rolfn.tls.crypto.NullCompression;
import org.pvv.rolfn.tls.crypto.NullEncryption;
import org.pvv.rolfn.tls.crypto.Prf;

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

	private Encryption readEncryption = NullEncryption.NULL;
	private Compression readCompression = NullCompression.NULL;
	private Encryption writeEncryption = NullEncryption.NULL;
	private Compression writeCompression = NullCompression.NULL;
	private Prf prf = null;
	
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
		ByteBuffer buf = ByteBuffer.allocate(5);
		buf.order(ByteOrder.BIG_ENDIAN);
		int readCnt = channel.read(buf);
		switch(readCnt) {
		case -1:
		case 0:
			log.debug("reading message seq="+seqCnt+", no data read");
			return null;
		case 5:
			break;
		default:
			// what to do?
			// should save this and continue reading later, but not now...
			log.warn("reading message seq="+seqCnt+", incomplete TLS header, size: "+readCnt);
			throw new IOException("broken TLS-header");
		}
		
		// the channel has written to the buffer, to start reading we need to flip...
		buf.flip();
		TLSCiphertext ciphertext = new TLSCiphertext(ContentType.read(buf));
		ProtocolVersion version = ProtocolVersion.read(buf); // TODO something useful with this...
		int length = buf.getShort();

		buf = ByteBuffer.allocate(length);
		int inputMessageSize = 0;
		while (buf.hasRemaining()) {
			readCnt = channel.read(buf);
			if (readCnt == -1) {
				throw new EOFException("unexpected end-of-stream");
			}
			inputMessageSize += readCnt;
		}

		if(log.isDebugEnabled()) {
			log.debug("reading message seq="+seqCnt+", length="+length+", msg size="+inputMessageSize+", content type: "+ciphertext.getContentType());
		}
		
		buf.flip();
		
		ciphertext.setData(buf);
		
		TLSCompressed compressed = readEncryption.decrypt(ciphertext);
		TLSPlaintext plaintext = readCompression.decompress(compressed);
		seqCnt++;
		return plaintext;
	}

	/**
	 * compress, add verification, encrypt and write.
	 * @param msg message to write
	 * @throws IOException 
	 */
	private void transformAndWrite(TLSPlaintext msg) throws IOException {
		log.debug("write message to channel type:"+msg.getContentType()+", size:"+msg.getLength());
		TLSCompressed compressed = writeCompression.compress(msg);
		TLSCiphertext ciphertext = writeEncryption.encrypt(compressed);
		
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
	 * commit(). The buffer position must be at the appropriate point to start
	 * reading, and the limit must be at the end. Thus: call flip() before writing.
	 * 
	 * @param type
	 *            type of message to send
	 * @param data
	 *            data to send.
	 */
	public void writeMessage(ContentType type, ByteBuffer data) {
		if(log.isDebugEnabled()) {
			log.debug("write message type="+type);
		}
		if (type == null) {
			throw new NullPointerException("content type cannot be null");
		}
		if (data == null) {
			data = ByteBuffer.allocate(0);
		}
		if (pendingOutput == null) {
			pendingOutput = new ArrayList<TLSPlaintext>();
		}
		TLSPlaintext plaintext = new TLSPlaintext(type);
		plaintext.setData(data);
		pendingOutput.add(plaintext);
	}

	/**
	 * Sends pending output to channel.
	 * @throws IOException
	 */
	public void commit() throws IOException {
		log.debug("commit data to output channel");
		if (pendingOutput == null || pendingOutput.size() == 0) {
			// noop
			return;
		}

		List<TLSPlaintext> output = combinePendingOutput();

		splitAndWrite(output);
		
		pendingOutput = null;
	}

	/**
	 * split oversized messages, then transform and write.
	 * 
	 * @param output list of messages to output
	 * @throws IOException 
	 */
	private void splitAndWrite(List<TLSPlaintext> output) throws IOException {
		for(TLSPlaintext msg: output) {
			ByteBuffer inputData = msg.getData();
			for(ByteBuffer split: ByteBufferUtils.splitAndIterate(inputData, maxRecordSize)) {
				TLSPlaintext splitMsg = new TLSPlaintext(msg.getContentType());
				splitMsg.setData(split);
				transformAndWrite(splitMsg);
			}
		}
	}

	/**
	 * collect records with same content into one large record.
	 * 
	 * @return list of combined records
	 */
	private List<TLSPlaintext> combinePendingOutput() {
		// if pendingOutput.size() == 1, we might as well just return pendingOutput, but this seems like premature optimization...
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
		log.debug("combining messages "+start+"-"+end+", total size "+size+", content type "+contentType);
		if (end - start == 1) {
			return pendingOutput.get(start);
		}
		ByteBuffer buf = ByteBuffer.allocate(size);
		for (int i = start; i < end; i++) {
			buf.put(pendingOutput.get(i).getData());
		}
		log.debug("... actually put: "+buf.position());
		buf.flip();
		TLSPlaintext tlsPlaintext = new TLSPlaintext(contentType);
		tlsPlaintext.setData(buf);
		return tlsPlaintext;
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

	public Prf getPrf() {
		if(prf == null) {
			synchronized(this) {
				if(prf == null) {
					prf = Prf.newInstance(params.getPrfAlgorithm());
				}
			}
		}
		return prf;
	}
}
