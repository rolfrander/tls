package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

/**
 * This is the byte string representation of an elliptic curve point following
 * the conversion routine in Section 4.3.6 of ANSI X9.62 [7]. This byte string
 * may represent an elliptic curve point in uncompressed or compressed format;
 * it MUST conform to what the client has requested through a Supported Point
 * Formats Extension if this extension was used.
 * 
 * @author RolfRander
 * 
 */
public class ECPoint {
	private byte[] point;
	
	private ECPoint(ByteBuffer buf) {
		point = ByteBufferUtils.readArray8(buf);
	}

	protected static ECPoint read(ByteBuffer buf) {
		return new ECPoint(buf);
	}

	public byte[] getPoint() {
		return point;
	}

}
