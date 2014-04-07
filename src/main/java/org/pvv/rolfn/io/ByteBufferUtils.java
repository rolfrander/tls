package org.pvv.rolfn.io;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public final class ByteBufferUtils {

	final public static int getUnsignedByte(ByteBuffer buf) {
		return ((int)buf.get()) & 0xff;
	}
	
	final public static int getUnsignedShort(ByteBuffer buf) {
		return buf.getShort() & 0xffff;
	}
	
	final public static int getUnsigned24(ByteBuffer buf) {
		int length = (0xff & buf.get());
		length = (length << 8) | (0xff & buf.get());
		length = (length << 8) | (0xff & buf.get());
		return length;
	}
	
	final public static void putUnsigned24(ByteBuffer buf, int value) {
		buf.put((byte)(value >> 16));
		buf.put((byte)(value >> 8));
		buf.put((byte)value);
	}
	
	final public static int getUnsigned31(ByteBuffer buf) {
		return buf.getInt();
	}
	
	final static public byte[] readArray8(ByteBuffer buf) {
		int length = getUnsignedByte(buf);
		byte[] array = new byte[length];
		buf.get(array);
		return array;
	}

	final static public byte[] readArray16(ByteBuffer buf) {
		int length = getUnsignedShort(buf);
		byte[] array = new byte[length];
		buf.get(array);
		return array;
	}

	final static public byte[] readArray24(ByteBuffer buf) {
		int length = getUnsigned24(buf);
		byte[] array = new byte[length];
		buf.get(array);
		return array;
	}

	final static public byte[] readArray31(ByteBuffer buf) {
		int length = getUnsigned31(buf);
		byte[] array = new byte[length];
		buf.get(array);
		return array;
	}
	
	final static public void writeArray8(ByteBuffer buf, byte[] data) {
		buf.put((byte)data.length);
		buf.put(data);
	}
	
	final static public void writeArray16(ByteBuffer buf, byte[] data) {
		buf.putShort((short)data.length);
		buf.put(data);
	}
	
	final static public void writeArray24(ByteBuffer buf, byte[] data) {
		putUnsigned24(buf, data.length);
		buf.put(data);
	}
	
	final static public void writeArray31(ByteBuffer buf, byte[] data) {
		buf.putInt((int)data.length);
		buf.put(data);
	}
	
	final static public ByteBuffer subBuffer24(ByteBuffer buf) {
		int len = getUnsigned24(buf);
		byte[] array = buf.array();
		int arrayOffset = buf.arrayOffset();
		int position = buf.position();
		buf.position(position+len);
		return ByteBuffer.wrap(array, arrayOffset+position, len);
	}
	
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
