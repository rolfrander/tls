package org.pvv.rolfn.asn1;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

/**
 * ASN.1-encoded printable string. Rules according to X.690-0207:
 * <p>
 * 8.21 Encoding for values of the restricted character string types
 * </p><p>
 * 8.21.1 The data value consists of a string of characters from the character
 * set specified in the ASN.1 type definition. 
 * </p><p>
 * 8.21.2 Each data value shall be encoded independently of other data values of
 * the same type.
 * </p><p>
 * 8.21.3 Each character string type shall be encoded as if it had been
 * declared: [UNIVERSAL x] IMPLICIT OCTET STRING where x is the number of the
 * universal class tag assigned to the character string type in ITU-T Rec. X.680
 * | ISO/IEC 8824-1. The value of the octet string is specified in 8.21.4 and
 * 8.21.5.
 * </p><p>
 * 8.21.4 Where a character string type is specified in ITU-T Rec. X.680 |
 * ISO/IEC 8824-1 by direct reference to an enumerating table (NumericString and
 * PrintableString), the value of the octet string shall be that specified in
 * </p><p>
 * 8.21.5 for a VisibleString type with the same character string value.
 * </p><p>
 * 8.21.5 For restricted character strings apart from UniversalString and
 * BMPString, the octet string shall contain the octets specified in ISO/IEC
 * 2022 for encodings in an 8-bit environment, using the escape sequence and
 * character codings registered in accordance with ISO 2375.
 * </p><p>
 * 8.21.5.1 An escape sequence shall not be used unless it is one of those
 * specified by one of the registration numbers used to define the character
 * string type in ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * </p><p>
 * 8.21.5.2 At the start of each string, certain registration numbers shall be
 * assumed to be designated as G0 and/or C0 and/or C1, and invoked (using the
 * terminology of ISO/IEC 2022). These are specified for each type in Table 3,
 * together with the assumed escape sequence they imply.
 * </p>
 * 
 * @author RolfRander
 * 
 */
public class ASN1PrintableString extends ASN1Object {
	private static final Charset CHARSET_ASCII = Charset.forName("ASCII");
	private String content;
	
	protected ASN1PrintableString(ASN1PC form, int length, ByteBuffer buf) {
		super(ASN1Type.Universal, form, ASN1UniversalTag.PrintableString, null);
		// details are incomprehensible, lets just assume ascii...
		byte[] data = new byte[length];
		buf.get(data);
		content = new String(data, CHARSET_ASCII);
	}
	
	public void prettyPrint(int indent) {
		System.out.println(String.format("%s%s \"%s\"", SPACE.subSequence(0, indent), tag, toString()));
	}

	public String toString() {
		return content;
	}
}
