package org.pvv.rolfn.asn1;

public class ASN1Null extends ASN1Object {
	protected ASN1Null() {
		super(ASN1Type.Universal, ASN1PC.Primitive, ASN1UniversalTag.NULL, null);
		// TODO Auto-generated constructor stub
	}

	@Override
	public String toString() {
		return "NULL";
	}
}
