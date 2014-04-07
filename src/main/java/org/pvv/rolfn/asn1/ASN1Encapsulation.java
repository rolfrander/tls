package org.pvv.rolfn.asn1;

import java.nio.ByteBuffer;
import java.util.Collection;

public class ASN1Encapsulation extends ASN1Object {
	private ASN1Object content;
	
	protected ASN1Encapsulation(ASN1Type asn1type, ASN1Tag tag, ByteBuffer buf, int length) {
		super(asn1type, ASN1PC.Constructed, tag, null);
		content = ASN1Object.read(buf);
	}

	@Override
	public void prettyPrint(int indent) {
		System.out.println(String.format("%s%s {", SPACE.subSequence(0, indent), tag));		
		content.prettyPrint(indent+2);
		System.out.println(String.format("%s}", SPACE.subSequence(0, indent)));		
	}
	
	public ASN1Object getContent() {
		return content;
	}

}
