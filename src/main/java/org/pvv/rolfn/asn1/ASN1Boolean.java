package org.pvv.rolfn.asn1;

import java.nio.ByteBuffer;

public class ASN1Boolean extends ASN1Object {
	private boolean value;
	public ASN1Boolean(int length, ByteBuffer buf) {
		super(ASN1Type.Universal, ASN1PC.Primitive, ASN1UniversalTag.BOOLEAN, null);
		if(length != 1) {
			throw new IllegalArgumentException("Dont know how to handle boolean of length "+length);
		}
		value = (buf.get() > 0);
	}

	public boolean isTrue() {
		return value;
	}
	
	public boolean isFalse() {
		return !value;
	}
	
	@Override
	public String toString() {
		return value ? "true" : "false";
	}
}
