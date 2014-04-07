package org.pvv.rolfn.asn1;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class ASN1UTF8String extends ASN1Object {

	private static final Charset CHARSET_UTF8 = Charset.forName("UTF8");
	private String content;
	
	protected ASN1UTF8String(ASN1PC form, int length, ByteBuffer buf) {
		super(ASN1Type.Universal, form, ASN1UniversalTag.UTF8String, null);
		byte[] data = new byte[length];
		buf.get(data);
		content = new String(data, CHARSET_UTF8);
	}
	
	public void prettyPrint(int indent) {
		System.out.println(String.format("%s%s \"%s\"", SPACE.subSequence(0, indent), tag, toString()));
	}

	public String toString() {
		return content;
	}

}
