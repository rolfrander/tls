package org.pvv.rolfn.tls;

import static org.junit.Assert.*;
import org.junit.Test;

public class TestUtils {

	public static final byte[] hexToByteArray(String hexData) {
		char[] data = hexData.toCharArray();
		int length = hexData.length();
		byte ret[] = new byte[length >> 1];
		for(int i=0; i<ret.length; i++) {
			byte high = (byte)(0x0f & Character.digit(data[2*i], 16));
			byte low = (byte)(0x0f & Character.digit(data[2*i+1], 16));
			ret[i] = (byte)(0xff & ((high << 4) | low));
		}
		return ret;
	}
	
	@Test
	public void testHexToByteArray() {
		String in = "a84bd1f2c34e5be1";
		byte[] out = new byte[] {(byte)0xa8, (byte)0x4b, (byte)0xd1, (byte)0xf2, (byte)0xc3, (byte)0x4e, (byte)0x5b, (byte)0xe1};
		assertArrayEquals(out, hexToByteArray(in));
	}
	
}
