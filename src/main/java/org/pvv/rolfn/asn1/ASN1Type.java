package org.pvv.rolfn.asn1;

public enum ASN1Type {
	Universal      (0), 
	Application    (1<<6), 
	ContextSpecific(2<<6), 
	Private        (3<<6);
	
	private int bit78;

	private ASN1Type(int bit78) {
		this.bit78=bit78;
	}
	
	public int getId() {
		return bit78;
	}
	
	public static ASN1Type fromId(int id) {
		switch( (id & 0xc0) >> 6) {
		case 0: return Universal;
		case 1: return Application;
		case 2: return ContextSpecific;
		case 3: return Private;
		default: return null; // there is no way to get here, but the java-compiler doesn't see that...
		}
	}
}
