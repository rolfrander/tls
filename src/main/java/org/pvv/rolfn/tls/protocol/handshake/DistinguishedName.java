package org.pvv.rolfn.tls.protocol.handshake;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.pvv.rolfn.asn1.ASN1Object;
import org.pvv.rolfn.asn1.ASN1Sequence;
import org.pvv.rolfn.asn1.ASN1Set;
import org.pvv.rolfn.asn1.OID;
import org.pvv.rolfn.io.ByteBufferUtils;
import org.pvv.rolfn.tls.protocol.handshake.DistinguishedName.AttributeTypeAndDistinguishedValue;

public class DistinguishedName {
	public static final class AttributeTypeAndDistinguishedValue {
		OID oid;
		String value;
		@Override public String toString() {
			StringBuilder b = new StringBuilder();
			b.append(oid.toString());
			if(oid.getName() != null) {
				b.append(" (");
				b.append(oid.getName());
				b.append(')');
			}
			b.append('=');
			b.append(value);
			return b.toString();
		}
		
		@Override public boolean equals(Object o) {
			if(!(o instanceof DistinguishedName.AttributeTypeAndDistinguishedValue)) {
				return false;
			}
			AttributeTypeAndDistinguishedValue other = (AttributeTypeAndDistinguishedValue)o;
			return other.oid.equals(oid) && other.value.equals(value);
		}
	}

	private byte[] data;
	private Collection<AttributeTypeAndDistinguishedValue> attributes = new ArrayList<AttributeTypeAndDistinguishedValue>();
	
	/**
	 * @throws ClassCastException if DN read from ByteBuffer is not ASN1Sequence
	 * @param buf
	 */
	private DistinguishedName(ByteBuffer buf) {
		ASN1Object dn;
		dn = ASN1Object.read(buf);
		// will give class cast exception if dn is not a sequence, this is ok...
		parseRdnSequence((ASN1Sequence) dn);
	}

	static protected DistinguishedName read(ByteBuffer buf) {
		return new DistinguishedName(buf);
	}
	
	public DistinguishedName() {
	}

	public DistinguishedName addRDN(OID oid, String value) {
		AttributeTypeAndDistinguishedValue attr = new AttributeTypeAndDistinguishedValue();
		attr.oid = oid;
		attr.value = value;
		attributes.add(attr);
		return this;
	}
	
	private void parseRdnSequence(ASN1Sequence dn) {
		for(ASN1Object o: dn.getContent()) {
			parseRdn((ASN1Set) o);
		}
	}

	private void parseRdn(ASN1Set rdn) {
		for(ASN1Object attributeValueAssertion: rdn.getContent()) {
			parseAttributeValueAssertion((ASN1Sequence) attributeValueAssertion);
		}
	}

	private void parseAttributeValueAssertion(ASN1Sequence attributeValueAssertion) {
		Iterator<ASN1Object> i = attributeValueAssertion.getContent().iterator();
		AttributeTypeAndDistinguishedValue attr = new AttributeTypeAndDistinguishedValue();
		attr.oid = (OID) i.next();
		attr.value = i.next().toString();
		attributes.add(attr);
	}
	
	/**
	 * Simple field-by-field compare, in the order given. Not anywhere near X.501... 
	 */
	@Override
	public boolean equals(Object o) {
		if(!(o instanceof DistinguishedName)) {
			return false;
		}
		DistinguishedName other = (DistinguishedName)o;
		if(other.attributes.size() != attributes.size()) {
			return false;
		}
		Iterator<AttributeTypeAndDistinguishedValue> i1 = attributes.iterator();
		Iterator<AttributeTypeAndDistinguishedValue> i2 = other.attributes.iterator();
		while(i1.hasNext() && i2.hasNext()) {
			if(!i1.next().equals(i2.next())) {
				return false;
			}
		}
		return true;
	}
}
