package org.pvv.rolfn.asn1;

import java.nio.ByteBuffer;
import java.util.*;

import org.pvv.rolfn.tls.protocol.record.CipherSuite;

public enum ASN1UniversalTag implements ASN1Tag {
	EOC(0),
	BOOLEAN(1),
	INTEGER(2),
	BIT_STRING(3),
	OCTET_STRING(4),
	NULL(5),
	OBJECT_IDENTIFIER(6),
	Object_Descriptor(7),
	EXTERNAL(8),
	REAL(9),
	ENUMERATED(10),
	EMBEDDED_PDV(11),
	UTF8String(12),
	RELATIVE_OID(13),
	reserved14(14),
	reserved15(15),
	SEQUENCE(16),
	SET(17),
	NumericString(18),
	PrintableString(19),
	T61String(20),
	VideotexString(21),
	IA5String(22),
	UTCTime(23),
	GeneralizedTime(24),
	GraphicString(25),
	VisibleString(26),
	GeneralString(27),
	UniversalString(28),
	CHARACTER_STRING(29),
	BMPString(30),
	LongForm(31);
	
	private int id;
	static private Map<Integer,ASN1UniversalTag> tags;
	
	private ASN1UniversalTag(int id) {
		this.id = id;
	}

	synchronized private static void getSuites() {
		if(tags == null) {
			tags = new TreeMap<Integer,ASN1UniversalTag>();
			for(ASN1UniversalTag t: ASN1UniversalTag.values()) {
				tags.put(t.id, t);
			}
		}
	}
	
	public static ASN1UniversalTag fromId(int id) {
		if(tags == null) {
			getSuites();
		}
		return tags.get(id & 0x1f);
	}

}
