package org.pvv.rolfn.io;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

public class ByteBufferUtilsTest {

	private static final byte[] testbuffercontent = "abcdefghijklmnopqrstuvwxyz".getBytes(Charset.forName("UTF-8"));
	private byte[] testbuffer;

	private int fill(byte src[], byte dst[], int start, int lensz) {
		int len = src.length;
		for(int i=lensz-1; i>=0; i--) {
			dst[i+start] = (byte) (0xff & len);
			len >>= 8;
		}
		start += lensz;
		for(int i=0; i<src.length; i++) {
			dst[start++] = src[i];
		}
		return start;
	}
	
	@Before
	public void setUp() {
		int l = testbuffercontent.length;
		testbuffer = new byte[l*4+1+2+3+4];
		int i=fill(testbuffercontent, testbuffer, 0, 1);
		i=fill(testbuffercontent, testbuffer, i, 2);
		i=fill(testbuffercontent, testbuffer, i, 3);
		i=fill(testbuffercontent, testbuffer, i, 4);
	}
	
	@Test
	public void testReadArray() {
		ByteBuffer buf = ByteBuffer.wrap(testbuffer);
		assertArrayEquals(testbuffercontent, ByteBufferUtils.readArray8(buf));;
		assertArrayEquals(testbuffercontent, ByteBufferUtils.readArray16(buf));;
		assertArrayEquals(testbuffercontent, ByteBufferUtils.readArray24(buf));;
		assertArrayEquals(testbuffercontent, ByteBufferUtils.readArray31(buf));;
	}

	public void testReadInt() {
		byte[] data = { (byte)0xff, (byte)0x00, (byte)0xff, (byte)0x00, (byte)0x00, (byte)0xff, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xff, (byte)0x00, (byte)0x06, (byte)0x85 };
		ByteBuffer buf = ByteBuffer.wrap(testbuffer);
		assertEquals(255, ByteBufferUtils.getUnsignedByte(buf));
		assertEquals(255, ByteBufferUtils.getUnsignedShort(buf));
		assertEquals(255, ByteBufferUtils.getUnsigned24(buf));
		assertEquals(255, ByteBufferUtils.getUnsigned31(buf));
		assertEquals(1669, ByteBufferUtils.getUnsigned24(buf));
	}
	
}
