package org.pvv.rolfn.asn1;

import java.nio.ByteBuffer;
import java.util.Collection;

abstract public class ASN1Collection extends ASN1Object {
	private Collection<ASN1Object> content;
	
	protected abstract Collection<ASN1Object> newCollection();
	
	protected ASN1Collection(ASN1UniversalTag tag, int length, ByteBuffer buf) {
		super(ASN1Type.Universal, ASN1PC.Constructed, tag, null);
		content = newCollection();
		int start = buf.position();
		while(buf.position() < (start+length)) {
			content.add(ASN1Object.read(buf));
		}
	}
	
	@Override
	public void prettyPrint(int indent) {
		System.out.println(String.format("%s%s {", SPACE.subSequence(0, indent), tag));		
		for(ASN1Object o: content) {
			o.prettyPrint(indent+2);
		}
		System.out.println(String.format("%s}", SPACE.subSequence(0, indent)));		
	}
	
	public Collection<ASN1Object> getContent() {
		return content;
	}
	
	@Override
	public String toString() {
		return this.getClass().getSimpleName()+" size: "+content.size();
	}

}
