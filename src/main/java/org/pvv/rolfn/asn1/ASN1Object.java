package org.pvv.rolfn.asn1;

import java.nio.ByteBuffer;

public class ASN1Object {
	protected ASN1Type type;
	protected ASN1PC pc;
	protected ASN1Tag tag;
	private byte[] value;

	protected final static String SPACE="                                           ";
	
	protected ASN1Object(ASN1Type asn1type, ASN1PC pc, ASN1Tag tag, byte[] value) {
		this.type = asn1type;
		this.pc = pc;
		this.tag = tag;
		this.value = value;
	}
	
	public String toString() {
		StringBuilder hexvalue = new StringBuilder();
		for(byte b: value) {
			hexvalue.append(String.format(" %02x", b));
		}
		return hexvalue.toString();
	}
	
	protected void prettyPrintHex(int indent) {
		System.out.println(String.format("%s%s %s", SPACE.subSequence(0, indent), tag, pc==ASN1PC.Constructed?"(c)":""));		
		StringBuilder hexvalue = new StringBuilder();
		int linelen = 0;
		for(byte b: value) {
			hexvalue.append(String.format(" %02x", b));
			if((++linelen) > 15) {
				System.out.println(String.format("%s%s", SPACE.subSequence(0, indent+2), hexvalue));
				hexvalue = new StringBuilder();
				linelen = 0;
			}
		}
		if(linelen > 0) {
			System.out.println(String.format("%s%s", SPACE.subSequence(0, indent+2), hexvalue));
		}
	}
	
	public void prettyPrint(int indent) {
		if(this.getClass() == ASN1Object.class) {
			// sort of ugly non-oo hack, but to provide a nice default implementation for subclasses
			// and have different functionality in the base class
			prettyPrintHex(indent);
		} else {
			System.out.println(String.format("%s%s %s%s", SPACE.subSequence(0, indent), tag, pc==ASN1PC.Constructed?"(c)":"", toString()));
		}
	}
	
	public static ASN1Object read(ByteBuffer buf) {
		byte identifier = buf.get();

		int length = getLength(buf);
		
		ASN1Type type = ASN1Type.fromId(identifier);
		ASN1PC pc = ASN1PC.fromId(identifier);
		ASN1Tag tag = null;
		switch(type) {
		case Universal:
			tag = ASN1UniversalTag.fromId(identifier);
			
			switch((ASN1UniversalTag)tag) {
			case BOOLEAN:  return new ASN1Boolean(length, buf);
			case INTEGER:  return new ASN1Integer(length, buf);
			case NULL:     return new ASN1Null();
			case SET:      return new ASN1Set(length, buf);
			case SEQUENCE: return new ASN1Sequence(length, buf);
			case OBJECT_IDENTIFIER: return OID.read(length, buf);
			case PrintableString: return new ASN1PrintableString(pc, length, buf);
			case UTF8String: return new ASN1UTF8String(pc, length, buf);
			}
			break;
		/*
		case Application:
		case ContextSpecific:
		case Private:
		*/
		default:
			tag = ASN1ApplicationTag.fromId(identifier, type);
		}
		if(pc == ASN1PC.Constructed) {
			return new ASN1Encapsulation(type, tag, buf, length);
		}
		byte content[] = new byte[length];
		buf.get(content);
		return new ASN1Object(type, pc, tag, content);
	}

	protected static int getLength(ByteBuffer buf) {
		int length = 0;
		byte l = buf.get();
		if(l == 0x80) {
			throw new IllegalArgumentException("indenfinite length not supported");
		}
		if( (l & 0x80) == 0) {
			// short form
			length = l;
		} else {
			// long form
			int cnt = l & 0x7f;
			if(cnt > 4) {
				throw new IllegalArgumentException("length must be max 4 bytes, first length octet is: "+l);
			}
			while(cnt > 0) {
				l = buf.get();
				if(cnt == 4 && (l & 0x80) > 0) {
					throw new IllegalArgumentException("length is 32 bits wide, first octet of long form is: "+l);
				}
				length = (length << 8) | ((int)l & 0xff);
				cnt--;
			}
		}
		return length;
	}
}
