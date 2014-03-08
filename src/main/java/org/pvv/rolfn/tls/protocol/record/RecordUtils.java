package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public final class RecordUtils {

	final public static int getUnsignedByte(ByteBuffer buf) {
		return buf.get() & 0xff;
	}
	
	final public static int getUnsignedShort(ByteBuffer buf) {
		return buf.getShort() & 0xffff;
	}
	
	final public static int getUnsigned24(ByteBuffer buf) {
		int length = buf.get();
		length = length << 8 & buf.get();
		length = length << 8 & buf.get();
		return length;
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

}
