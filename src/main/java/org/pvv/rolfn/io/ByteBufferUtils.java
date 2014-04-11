package org.pvv.rolfn.io;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

/**
 * ByteBuffer-helper functions for handling some other datatypes and arrays with length.
 * 
 * @author RolfRander
 *
 */
public final class ByteBufferUtils {

	/**
	 * Returns 8 unsigned bits as an integer.
	 *  
	 * @param buf
	 * @return
	 */
	final public static int getUnsignedByte(ByteBuffer buf) {
		return ((int)buf.get()) & 0xff;
	}
	
	/**
	 * Returns 16 unsigned bits as an integer. Big endian.
	 * 
	 * @param buf
	 * @return
	 */
	final public static int getUnsignedShort(ByteBuffer buf) {
		return buf.getShort() & 0xffff;
	}
	
	/**
	 * Retuurn 24 unsigned bits as an integer. Big endian.
	 * @param buf
	 * @return
	 */
	final public static int getUnsigned24(ByteBuffer buf) {
		int length = (0xff & buf.get());
		length = (length << 8) | (0xff & buf.get());
		length = (length << 8) | (0xff & buf.get());
		return length;
	}

	/**
	 * Returns 31 bits of an int, removing the sign bit.
	 * @param buf
	 * @return
	 */
	final public static int getUnsigned31(ByteBuffer buf) {
		return buf.getInt() & 0x7fffffff;
	}
	
	/**
	 * Puts the 24 least significant bits of value in to the byte buffer, big endian.
	 * @param buf
	 * @param value
	 */
	final public static void putUnsigned24(ByteBuffer buf, int value) {
		buf.put((byte)(value >> 16));
		buf.put((byte)(value >> 8));
		buf.put((byte)value);
	}
	
	
	/**
	 * Reads an 8 bit array length followed by the actual array data.
	 * @param buf
	 * @return the array read
	 */
	final static public byte[] readArray8(ByteBuffer buf) {
		int length = getUnsignedByte(buf);
		byte[] array = new byte[length];
		buf.get(array);
		return array;
	}

	/**
	 * Reads an 16 bit array length followed by the actual array data.
	 * @param buf
	 * @return the array read
	 */
	final static public byte[] readArray16(ByteBuffer buf) {
		int length = getUnsignedShort(buf);
		byte[] array = new byte[length];
		buf.get(array);
		return array;
	}

	/**
	 * Reads an 24 bit array length followed by the actual array data.
	 * @param buf
	 * @return the array read
	 */
	final static public byte[] readArray24(ByteBuffer buf) {
		int length = getUnsigned24(buf);
		byte[] array = new byte[length];
		buf.get(array);
		return array;
	}

	/**
	 * Reads an 31 bit array length followed by the actual array data.
	 * @param buf
	 * @return the array read
	 */
	final static public byte[] readArray31(ByteBuffer buf) {
		int length = getUnsigned31(buf);
		byte[] array = new byte[length];
		buf.get(array);
		return array;
	}
	
	/**
	 * writes the length of data as an 8 bit unsigned value, followed by the actual data.
	 * does not check that the length of the data-array actually fits in the lengths field.
	 * @param buf
	 * @param data
	 */
	final static public void writeArray8(ByteBuffer buf, byte[] data) {
		buf.put((byte)data.length);
		buf.put(data);
	}
	
	/**
	 * writes the length of data as an 16 bit unsigned value, followed by the actual data.
	 * does not check that the length of the data-array actually fits in the lengths field.
	 * @param buf
	 * @param data
	 */
	final static public void writeArray16(ByteBuffer buf, byte[] data) {
		buf.putShort((short)data.length);
		buf.put(data);
	}
	
	/**
	 * writes the length of data as an 24 bit unsigned value, followed by the actual data.
	 * does not check that the length of the data-array actually fits in the lengths field.
	 * @param buf
	 * @param data
	 */
	final static public void writeArray24(ByteBuffer buf, byte[] data) {
		putUnsigned24(buf, data.length);
		buf.put(data);
	}
	
	/**
	 * writes the length of data as an 31 bit unsigned value, followed by the actual data.
	 * does not check that the length of the data-array actually fits in the lengths field.
	 * @param buf
	 * @param data
	 */
	final static public void writeArray31(ByteBuffer buf, byte[] data) {
		buf.putInt((int)data.length);
		buf.put(data);
	}
	
	/**
	 * Reads a 24 bit length field and returns a ByteBuffer corresponding to the array of
	 * bytes of this length following the length field.
	 * @param buf
	 * @return
	 */
	final static public ByteBuffer subBuffer24(ByteBuffer buf) {
		int len = getUnsigned24(buf);
		byte[] array = buf.array();
		int arrayOffset = buf.arrayOffset();
		int position = buf.position();
		buf.position(position+len);
		return ByteBuffer.wrap(array, arrayOffset+position, len);
	}

	/**
	 * Returns an InputStream wrapping a ByteBuffer.
	 * @param buf
	 * @return
	 */
	final static public InputStream asInputStream(final ByteBuffer buf) {
		return new InputStream() {

		    public int read() throws IOException {
		        if (!buf.hasRemaining()) {
		            return -1;
		        }
		        return buf.get() & 0xFF;
		    }

		    public int read(byte[] bytes, int off, int len)
		            throws IOException {
		        if (!buf.hasRemaining()) {
		            return -1;
		        }

		        len = Math.min(len, buf.remaining());
		        buf.get(bytes, off, len);
		        return len;
		    }
		    
		    public void mark(int readlimit) {
		    	buf.mark();
		    }
		    
		    public void reset() {
		    	buf.reset();
		    }
		    
		    public boolean markSupported() {
		    	return true;
		    }
		};
	}

}
