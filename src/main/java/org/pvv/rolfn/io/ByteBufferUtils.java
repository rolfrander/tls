package org.pvv.rolfn.io;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Iterator;

import org.apache.log4j.Logger;

/**
 * ByteBuffer-helper functions for handling some other datatypes and arrays with
 * length.
 * 
 * @author RolfRander
 * 
 */
public final class ByteBufferUtils {
	static private final Logger log = Logger.getLogger(ByteBufferUtils.class);

	/**
	 * Returns 8 unsigned bits as an integer.
	 * 
	 * @param buf
	 * @return
	 */
	final public static int getUnsignedByte(ByteBuffer buf) {
		return ((int) buf.get()) & 0xff;
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
	 * 
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
	 * 
	 * @param buf
	 * @return
	 */
	final public static int getUnsigned31(ByteBuffer buf) {
		return buf.getInt() & 0x7fffffff;
	}

	/**
	 * Puts the 24 least significant bits of value in to the byte buffer, big
	 * endian.
	 * 
	 * @param buf
	 * @param value
	 */
	final public static void putUnsigned24(ByteBuffer buf, int value) {
		buf.put((byte) (value >> 16));
		buf.put((byte) (value >> 8));
		buf.put((byte) value);
	}

	/**
	 * Puts the 24 least significant bits of value in to the byte buffer, big
	 * endian.
	 * 
	 * @param buf
	 * @param value
	 */
	final public static void putUnsigned24(ByteBuffer buf, int index, int value) {
		buf.put(index, (byte) (value >> 16)); index++;
		buf.put(index, (byte) (value >> 8));  index++;
		buf.put(index, (byte) value);
	}
	
	/**
	 * Reads an 8 bit array length followed by the actual array data.
	 * 
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
	 * 
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
	 * 
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
	 * 
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
	 * writes the length of data as an 8 bit unsigned value, followed by the
	 * actual data. does not check that the length of the data-array actually
	 * fits in the lengths field.
	 * 
	 * @param buf
	 * @param data
	 */
	final static public void writeArray8(ByteBuffer buf, byte[] data) {
		buf.put((byte) data.length);
		buf.put(data);
	}

	/**
	 * writes the length of data as an 16 bit unsigned value, followed by the
	 * actual data. does not check that the length of the data-array actually
	 * fits in the lengths field.
	 * 
	 * @param buf
	 * @param data
	 */
	final static public void writeArray16(ByteBuffer buf, byte[] data) {
		buf.putShort((short) data.length);
		buf.put(data);
	}

	/**
	 * writes the length of data as an 24 bit unsigned value, followed by the
	 * actual data. does not check that the length of the data-array actually
	 * fits in the lengths field.
	 * 
	 * @param buf
	 * @param data
	 */
	final static public void writeArray24(ByteBuffer buf, byte[] data) {
		putUnsigned24(buf, data.length);
		buf.put(data);
	}

	/**
	 * writes the length of data as an 31 bit unsigned value, followed by the
	 * actual data. does not check that the length of the data-array actually
	 * fits in the lengths field.
	 * 
	 * @param buf
	 * @param data
	 */
	final static public void writeArray31(ByteBuffer buf, byte[] data) {
		buf.putInt((int) data.length);
		buf.put(data);
	}

	/**
	 * Reads a 24 bit length field and returns a ByteBuffer corresponding to the
	 * array of bytes of this length following the length field.
	 * 
	 * @param buf
	 * @return
	 */
	final static public ByteBuffer subBuffer24(ByteBuffer buf) {
		int len = getUnsigned24(buf);
		byte[] array = buf.array();
		int arrayOffset = buf.arrayOffset();
		int position = buf.position();
		buf.position(position + len);
		return ByteBuffer.wrap(array, arrayOffset + position, len);
	}

	/**
	 * Returns an InputStream wrapping a ByteBuffer.
	 * 
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

			public int read(byte[] bytes, int off, int len) throws IOException {
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

	/**
	 * Returns a slice of the bytebuffer starting at mark with given length.
	 * 
	 * @param buf
	 * @param length
	 * @return
	 */
	final static public ByteBuffer sliceMarkToLength(ByteBuffer buf, int length) {
		int pos = buf.position();
		int lim = buf.limit();
		buf.reset();
		buf.limit(buf.position() + length);
		ByteBuffer save = buf.slice();
		buf.position(pos);
		buf.limit(lim);
		return save;
	}

	/**
	 * Returns a slice of the bytebuffer starting at the current position and with the given length.
	 * Updates position the the first position not included in returned buffer.
	 * 
	 * @param buf
	 * @param length
	 * @return
	 */
	final static public ByteBuffer slicePosToLength(ByteBuffer buf, int length) {
		int lim = buf.limit();
		int end = buf.position() + length;
		buf.limit(end);
		ByteBuffer save = buf.slice();
		buf.position(end);
		buf.limit(lim);
		return save;		
	}

	/**
	 * Concatenates two byte arrays.
	 * @param a1
	 * @param a2
	 * @return concatenated array. the returned array has length = a1.length+a2.length
	 */
	final static public byte[] concat(byte[] a1, byte[] a2) {
		byte[] ret = new byte[a1.length + a2.length];
		System.arraycopy(a1, 0, ret, 0, a1.length);
		System.arraycopy(a2, 0, ret, a1.length, a2.length);
		return ret;
	}

	/**
	 * split inputbuffer in chuncks of maxsize. Several maxsize values may be
	 * given, in which case these are used in turn, and the last is repeated
	 * until input is empty. For example, if maxsize = { 1, 5, 4 }, the first
	 * returned buffer will have size 1, the second 5 and any subsequent buffers
	 * will have size 4, except the last one which is size 4 or smaller.
	 * 
	 * @param in
	 * @param maxsize list of buffer sizes
	 * @return Iterable which returns a ByteBuffer-iterator iterating through
	 *         the split buffers.
	 */
	final static public Iterable<ByteBuffer> splitAndIterate(final ByteBuffer in, final int... maxsize) {
		return new Iterable<ByteBuffer>() {
			@Override
			public Iterator<ByteBuffer> iterator() {
				return new Iterator<ByteBuffer>() {
					boolean hasNext = true;
					int i = 0;

					@Override
					public boolean hasNext() {
						return hasNext;
					}

					@Override
					public ByteBuffer next() {
						ByteBuffer out;
						if (in.remaining() <= maxsize[i]) {
							hasNext = false;
							out = in.slice();
						} else {
							out = slicePosToLength(in, maxsize[i]);
						}
						if (i + 1 < maxsize.length) {
							i++;
						}
						return out;
					}

					@Override
					public void remove() {
						throw new UnsupportedOperationException();
					}
				};
			}
		};
	}
}
