package org.pvv.rolfn.asn1;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * ASN.1-encoded OID. Rules according to X.690-0207:
 * <p>
 * 8.19 Encoding of an object identifier value
 * </p><p>
 * 8.19.1 The encoding of an object identifier value shall be primitive.
 * </p><p>
 * 8.19.2 The contents octets shall be an (ordered) list of encodings of
 * subidentifiers (see 8.19.3 and 8.19.4) concatenated together. Each
 * subidentifier is represented as a series of (one or more) octets. Bit 8 of
 * each octet indicates whether it is the last in the series: bit 8 of the last
 * octet is zero; bit 8 of each preceding octet is one. Bits 7 to 1 of the
 * octets in the series ISO/IEC 8825-1:2003 (E) 14 ITU-T Rec. X.690 (07/2002)
 * collectively encode the subidentifier. Conceptually, these groups of bits are
 * concatenated to form an unsigned binary number whose most significant bit is
 * bit 7 of the first octet and whose least significant bit is bit 1 of the last
 * octet. The subidentifier shall be encoded in the fewest possible octets, that
 * is, the leading octet of the subidentifier shall not have the value 0x80.
 * </p><p>
 * 8.19.3 The number of subidentifiers (N) shall be one less than the number of
 * object identifier components in the object identifier value being encoded.
 * </p><p>
 * 8.19.4 The numerical value of the first subidentifier is derived from the
 * values of the first two object identifier components in the object identifier
 * value being encoded, using the formula: (X*40) + Y where X is the value of
 * the first object identifier component and Y is the value of the second object
 * identifier component.
 * </p><p>
 * NOTE – This packing of the first two object identifier components recognizes
 * that only three values are allocated from the root node, and at most 39
 * subsequent values from nodes reached by X = 0 and X = 1.
 * </p><p>
 * 8.19.5 The numerical value of the ith subidentifier, (2 ≤ i ≤ N) is that of
 * the (i + 1)th object identifier component.
 * </p>
 * 
 * @author RolfRander
 * 
 */
public class OID extends ASN1Object {

	private OID parent;
	
	private Map<Integer,OID> children = new HashMap<Integer,OID>();
	
	public static OID ROOT = new OID(null, null);
	
	private static Map<String,OID> names = new HashMap<String,OID>();
	
	private Integer id;
	
	private String string = null;
	
	private String name;

	public static final OID ITU_T           = ROOT.getChild(0, "itu-t");
	public static final OID ISO             = ROOT.getChild(1, "iso");
	public static final OID JOINT_ISO_ITU_T = ROOT.getChild(2, "joint-iso-itu-t");
	
	private OID(OID parent, Integer id) {
		super(ASN1Type.Universal, ASN1PC.Primitive, ASN1UniversalTag.OBJECT_IDENTIFIER, null);
		this.id = id; 
		this.parent = parent;
	}
	
	public OID getChild(Integer id) {
		if(children.containsKey(id)) {
			return children.get(id);
		} else {
			OID child = new OID(this, id);
			children.put(id, child);
			return child;
		}
	}
	
	public OID getChild(Integer id, String name) {
		return getChild(id).setName(name);
	}
	
	static public OID getById(Integer... subIds) {
		OID node = ROOT;
		for(Integer id: subIds) {
			node = node.getChild(id);
		}
		return node;
	}
	
	static public OID getByName(String name) {
		return names.get(name);
	}
	
	/**
	 * Returns a symbolic name describing this OID, if set. Returns null of no name is set.
	 * @return symbolic name of OID
	 */
	public String getName() {
		return name;
	}
	
	/**
	 * Sets the public name describing this OID. Also registers this name with the global
	 * name-to-OID-mapping. If another object is registered with this name, it is overwritten.
	 * If this object already has a name, the old name disappears from the global mapping.
	 * Remove name by setting name to null. 
	 */
	public OID setName(String name) {
		if(this.name != null) {
			names.remove(this.name);
			this.name = null;
		}
		if(name != null) {
			if(names.containsKey(name)) {
				names.get(name).name = null;
				names.remove(name);
			}
			this.name = name;
			names.put(name, this);
		}
		return this;
	}
	
	static protected OID read(int length, ByteBuffer buf) {
		
		int subId;
		int start = buf.position();
		OID node = ROOT;
		
		subId = getSubIdentifier(buf);
		
		// first subId-value is really subId1*40+subId2
		if(subId < 40) {
			node = node.getChild(0);
			node = node.getChild(subId);
		} else if(subId < 80) {
			node = node.getChild(1);
			node = node.getChild(subId-40);
		} else {
			node = node.getChild(2);
			node = node.getChild(subId-80);
		}

		while(buf.position() < (start+length)) {
			node = node.getChild(getSubIdentifier(buf));
		}
		return node;
	}

	static private int getSubIdentifier(ByteBuffer buf) {
		int subId = 0;
		byte b;
		int cnt = 0;
		do {
			b = buf.get();
			cnt++;
			if(cnt > 5) {
				throw new IllegalArgumentException("cannot handle subIds spanning more than 5 octets (= 35 bits)");
			}
			subId = (subId << 7) | (b & 0x7f);
		} while((b & 0x80) > 0);
		return subId;
	}

	private StringBuilder buildASN1String() {
		StringBuilder ret = null;
		if(this == ROOT) {
			ret = new StringBuilder();
			ret.append('{');
		} else {
			ret = parent.buildASN1String();
			if(name != null) {
				ret.append(name);
				ret.append('(');
				ret.append(id);
				ret.append(')');
			} else {
				ret.append(id);
			}
			ret.append(' ');
		}
		return ret;
	}
	
	public String getASN1String() {
		StringBuilder build = buildASN1String();
		build.append('}');
		return build.toString();
	}
	
	private StringBuilder buildString() {
		if(this == ROOT) {
			return new StringBuilder();
		} else {
			return parent.buildString().append(id).append('.');
		}
	}

	public String toString() {
		if(string == null) {
			// this string might be built twice if called concurrently from two different thread
			// but this doesn't matter, assume the overhead of synchronization is more than the
			// random double call
			StringBuilder oidString = buildString(); // includes a final dot '.'
			int len = oidString.length();
			string = oidString.substring(0, len-1);
		}
		return string;
	}
	
	public static void prettyPrintKnownOIDTree() {
		ROOT.prettyPrintTree(0);
	}

	private void prettyPrintTree(int indent) {
		StringBuilder sb = buildString();
		if(name != null) {
			sb.append("= ");
			sb.append(name);
		}
		System.out.print(SPACE.subSequence(0, indent));
		System.out.println(sb);
		for(OID c: children.values()) {
			c.prettyPrintTree(indent+2);
		}
	}
}
