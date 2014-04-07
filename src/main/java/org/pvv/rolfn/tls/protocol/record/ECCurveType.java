package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

/**
 * This message is used to convey the server's ephemeral ECDH public key (and
 * the corresponding elliptic curve domain parameters) to the client.
 * 
 * @author RolfRander
 * 
 */
public enum ECCurveType {
	/**
	 * Indicates the elliptic curve domain parameters are conveyed verbosely,
	 * and the underlying finite field is a prime field.
	 */
	explicit_prime(1),

	/**
	 * Indicates the elliptic curve domain parameters are conveyed verbosely,
	 * and the underlying finite field is a characteristic-2 field.
	 */
	explicit_char2(2),

	/**
	 * Indicates that a named curve is used. This option SHOULD be used when
	 * applicable.
	 */
	named_curve(3);

	private int id;

	private ECCurveType(int id) {
		this.id = id;
	}

	static protected ECCurveType read(ByteBuffer buf) {
		return byid(ByteBufferUtils.getUnsignedByte(buf));
	}
	
	static public ECCurveType byid(int id) {
		switch (id) {
		case 1:
			return explicit_prime;
		case 2:
			return explicit_char2;
		case 3:
			return named_curve;
		default:
			return null;
		}
	}

}
