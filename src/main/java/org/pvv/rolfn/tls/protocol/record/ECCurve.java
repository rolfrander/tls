package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

/**
 * These parameters specify the coefficients of the elliptic curve. Each value
 * contains the byte string representation of a field element following the
 * conversion routine in Section 4.3.3 of ANSI X9.62 [7].
 * 
 * @author RolfRander
 * 
 */
public class ECCurve {
	private byte a[];
	private byte b[];

	private ECCurve(ByteBuffer buf) {
		a = ByteBufferUtils.readArray8(buf);
		b = ByteBufferUtils.readArray8(buf);
	}
	
	static protected ECCurve read(ByteBuffer buf) {
		return new ECCurve(buf);
	}

	public byte[] getA() {
		return a;
	}

	public byte[] getB() {
		return b;
	}
	
	
}
