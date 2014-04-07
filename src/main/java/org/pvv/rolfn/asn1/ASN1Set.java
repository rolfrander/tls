package org.pvv.rolfn.asn1;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.HashSet;

public class ASN1Set extends ASN1Collection {

	protected ASN1Set(int length, ByteBuffer buf) {
		super(ASN1UniversalTag.SET, length, buf);
	}

	protected Collection<ASN1Object> newCollection() {
		return new HashSet<ASN1Object>();
	}
}
