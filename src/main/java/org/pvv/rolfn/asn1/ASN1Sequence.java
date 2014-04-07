package org.pvv.rolfn.asn1;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;

public class ASN1Sequence extends ASN1Collection {
	protected ASN1Sequence(int length, ByteBuffer buf) {
		super(ASN1UniversalTag.SEQUENCE, length, buf);
	}

	protected Collection<ASN1Object> newCollection() {
		return new ArrayList<ASN1Object>();
	}
}
