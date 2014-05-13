package org.pvv.rolfn;

import static org.junit.Assert.*;
import org.junit.Test;

public class TestUtils {

	public static final byte[] hexToByteArray(String hexData) {
		char[] charData = hexData.toCharArray();
		int length = hexData.length();
		byte data[] = new byte[length >> 1];
		int j=0;
		boolean ishigh = true;
		byte high=0, low=0;
		for(int i=0; i<charData.length; i++) {
			int digit = Character.digit(charData[i], 16);
			if(digit >= 0) {
				if(ishigh) {
					high = (byte)(0x0f & digit);
				} else {
					low = (byte)(0x0f & digit);
					data[j++] = (byte)(0xff & ((high << 4) | low));
				}
				ishigh = !ishigh;
			}
		}
		byte ret[] = new byte[j];
		System.arraycopy(data, 0, ret, 0, j);
		return ret;
	}
	
	@Test
	public void testHexToByteArray() {
		String in = "a84bd1f2c34e5be1";
		byte[] out = new byte[] {(byte)0xa8, (byte)0x4b, (byte)0xd1, (byte)0xf2, (byte)0xc3, (byte)0x4e, (byte)0x5b, (byte)0xe1};
		assertArrayEquals(out, hexToByteArray(in));
	}

	@Test
	public void testHexToByteArraySpace() {
		String in = "a8 4bd 1 f2 c34 e 5b e1";
		byte[] out = new byte[] {(byte)0xa8, (byte)0x4b, (byte)0xd1, (byte)0xf2, (byte)0xc3, (byte)0x4e, (byte)0x5b, (byte)0xe1};
		assertArrayEquals(out, hexToByteArray(in));
	}
	
}
