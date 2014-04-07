package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public enum ECBasisType {
	/**
	 * Indicates representation of a characteristic-2 field using a trinomial
	 * basis.
	 */
	ec_basis_trinomial(1),
	/**
	 * Indicates representation of a characteristic-2 field using a pentanomial
	 * basis.
	 */
	ec_basis_pentanomial(2);
	// (255)
	
	private int id;

	private ECBasisType(int id) {
		this.id = id;
	}

	protected static ECBasisType read(ByteBuffer buf) {
		return fromId(ByteBufferUtils.getUnsignedByte(buf));
	}

	public static ECBasisType fromId(int id) {
		switch (id) {
		case 1: return ec_basis_trinomial;
		case 2: return ec_basis_pentanomial;
		default:return null;
		}
	}
}
