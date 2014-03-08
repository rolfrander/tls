package org.pvv.rolfn.formatting;

public class FormatUtils {
	private static final char[] SPACE = "                                                              ".toCharArray();

	public static void printHex(byte[] data) {
		for(int i=0; i<data.length; i+=16) {
			StringBuilder buf = new StringBuilder(72);
			StringBuilder asc = new StringBuilder(16);
			buf.append(String.format("0x%05x", i));
			for(int j=0; (j<16) && ((i+j)<data.length); j++) {
				buf.append(String.format(" %02x", data[i+j]));
				if(data[i+j] >= 32 && data[i+j] < 127) {
					asc.append(String.format("%c", data[i+j]));
				} else {
					asc.append('.');
				}
			}
			
			buf.append(SPACE, 0, 56-buf.length());
			buf.append(asc);
			System.out.println(buf);
		}
	}
}
