package org.pvv.rolfn.asn1;

public enum ASN1PC {
	Primitive(0),
	Constructed(1<<5);
	
	private int bit6;
	
	private ASN1PC(int bit6) {
		this.bit6 = bit6;
	}
	
	public int getId() {
		return bit6;
	}
	
	public static ASN1PC fromId(int id) {
		switch( (id & 0x20) >> 5) {
		case 0: return Primitive;
		case 1: return Constructed;
		default: return null;
		}
	}
}
