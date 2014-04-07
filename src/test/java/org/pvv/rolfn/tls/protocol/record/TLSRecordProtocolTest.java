package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ShortBuffer;
import java.nio.channels.ByteChannel;

import org.junit.Test;

public class TLSRecordProtocolTest {

	public static final int K = 1024;
	public static final int RECORD_SIZE = 256;  // note that TLSRecordProtocol reserves 128 bytes as a buffer to avoid overflow
	public static final int MESSAGE_SIZE = 80;  // 3 msg == approx 2 records
	public static final byte[] data = new byte[8*K];
	
	/*
	 * Fill data like this:
	 * - each even position filled with an even number
	 * - each odd position filled with an odd number
	 * for two consecutive numbers, one even (e), one odd (o), the position of the even number is:
	 * pos = e*128 + o -1
	 */
	
	static {
		ByteBuffer buf = ByteBuffer.wrap(data);
		int i=0, j=1;
		while(buf.remaining() > 0) {
			buf.put((byte)i);
			buf.put((byte)j);
			//System.out.println(String.format("i=%d j=%d pos=%d", i, j, buf.position()));
			j += 2;
			if(j > 255) {
				i += 2;
				j = 1;
			}
		}
	}
	
	static int pos(byte b1, byte b2) {
		int o, e, a;
		if((b1 & 1) == 0) {
			e = (b1 & 0xff);
			o = (b2 & 0xff);
			a = 0;
		} else {
			e = (b2 & 0xff);
			o = (b1 & 0xff)+1;
			// corner case when e increase
			if(o == 256) {
				e -= 2;
			}
			a = 0;
		}
		int pos = e*128+o-1;
		//System.out.println(String.format("e=%d o=%d pos=%d", e, o, pos));
		return pos;
	}
	
	@Test public void buffercounter() {
		for(int i=0; i<data.length-1; i++) {
			assertEquals(i, pos(data[i], data[i+1]));
		}
	}
	
	/**
	 * Testing combinating, fragmenting and writing of TLS-packets to a
	 * ByteChannel. Testing algorithm:
	 * <ul>
	 * <li>Create a set of messages with the same type, size less than
	 * maxPacketSize but combined size of more than maxPacketSize</li>
	 * <li>Add some packets of different type</li>
	 * <li>Write all to a TLSRecordProtocol-object</li>
	 * <li>Check that the original messages are combined into large packets of
	 * maxPacketSize</li>
	 * <li>Then try reading them back</li>
	 * </ul>
	 * @throws IOException 
	 */
	@Test
	public void recordProtocol() throws IOException {
		SecurityParameters params = new SecurityParameters();
		params.setProtocolVersion(ProtocolVersion.TLS1_2);

		final ByteBuffer target = ByteBuffer.allocate(8 * K);
		ByteChannel channel = new ByteChannel() {

			@Override
			public int write(ByteBuffer src) throws IOException {
				int cnt = src.remaining();
				target.put(src);
				return cnt;
			}

			@Override
			public boolean isOpen() {
				return true;
			}

			@Override
			public void close() throws IOException {
			}

			@Override
			public int read(ByteBuffer dst) throws IOException {
				int n = Math.min(target.remaining(), dst.remaining());
				System.arraycopy(target.array(), target.position(), 
								 dst.array(), dst.position(),
								 n);
				target.position(target.position()+n);
				dst.position(dst.position()+n);
				return n;
			}
		};

		TLSRecordProtocol tls = new TLSRecordProtocol(channel, params);
		tls.setMaxRecordSize(128);
		
		byte[] msg;
		byte[] ccs = new byte[1];
		ccs[0] = (byte)1; // change cipher spec
		int pos = 0;
		// add some random handshakes
		for(int i=0; i<5; i++) {
			msg = new byte[MESSAGE_SIZE];
			System.arraycopy(data, pos, msg, 0, MESSAGE_SIZE);
			tls.writeMessage(ContentType.handshake, msg);
			pos += MESSAGE_SIZE;
		}
		// change cipher spec
		tls.writeMessage(ContentType.change_cipher_spec, ccs);
		// add some more handshake data
		msg = new byte[MESSAGE_SIZE];
		System.arraycopy(data, pos, msg, 0, MESSAGE_SIZE);
		tls.writeMessage(ContentType.handshake, msg);
		
		// commit data
		tls.commit();
		
		// now check...
		target.flip();
		
		TLSPlaintext record;
		int cnt = 0;
		record = tls.readMessage();
		while(record.getContentType() == ContentType.handshake) {
			for(int i=0; i<record.data.length-1; i++) {
				assertEquals(cnt, pos(record.data[i], record.data[i+1]));
				cnt++;
			}
			// skipping the last byte when counting, need to take that into account when checking...
			cnt++;
			record = tls.readMessage();
		}
		assertEquals(ContentType.change_cipher_spec, record.getContentType());
		record = tls.readMessage();
		for(int i=0; i<record.data.length-1; i++) {
			assertEquals(cnt, pos(record.data[i], record.data[i+1]));
			cnt++;
		}
		// check that end of data and number of bytes is as expected
		assertEquals(data[MESSAGE_SIZE*6-2], record.data[record.data.length-2]);
		assertEquals(data[MESSAGE_SIZE*6-1], record.data[record.data.length-1]);
		assertEquals(MESSAGE_SIZE*6-1, cnt);
	}
}
