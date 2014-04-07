package org.pvv.rolfn.asn1;

public class ASN1ApplicationTag implements ASN1Tag {
	private int tagNumber;
	private ASN1Type type;
	
	public ASN1ApplicationTag(int id, ASN1Type type) {
		this.tagNumber = id;
		this.type = type;
	}

	public static ASN1ApplicationTag fromId(byte identifier, ASN1Type type) {
		return new ASN1ApplicationTag(identifier & 0x1f, type);
	}
	
	@Override
	public String toString() {
		return "["+type+" "+tagNumber+"]";
	}
}
