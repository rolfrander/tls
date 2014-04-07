package org.pvv.rolfn.asn1;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class ASN1Integer extends ASN1Object {

	private BigInteger value;
	private byte[] data;
	
	public ASN1Integer(int length, ByteBuffer buf) {
		super(ASN1Type.Universal, ASN1PC.Primitive, ASN1UniversalTag.INTEGER, null);
		
		data = new byte[length];
		buf.get(data);
		
		value = new BigInteger(data);
	}

	@Override
	public String toString() {
		return value.toString();
	}
	
	public BigInteger getValue() {
		return value;
	}
	
	public byte[] getData() {
		return data;
	}
}
