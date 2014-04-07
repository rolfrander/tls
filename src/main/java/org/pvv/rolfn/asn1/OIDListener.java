package org.pvv.rolfn.asn1;

import org.antlr.v4.runtime.tree.TerminalNode;
import org.pvv.rolfn.asn1.parser.ASNBaseListener;
import org.pvv.rolfn.asn1.parser.ASNParser.AssignmentContext;
import org.pvv.rolfn.asn1.parser.ASNParser.ObjIdComponentsContext;
import org.pvv.rolfn.asn1.parser.ASNParser.ObjIdComponentsListContext;
import org.pvv.rolfn.asn1.parser.ASNParser.ObjectIdentifierValueContext;
import org.pvv.rolfn.asn1.parser.ASNParser.ValueAssignmentContext;

public class OIDListener extends ASNBaseListener {

	@Override
	public void exitAssignment(AssignmentContext ctx) {
		// TODO Auto-generated method stub
		ValueAssignmentContext va = ctx.valueAssignment();
		if(va != null) {
			if(va.type().builtinType() != null) {
				if(va.type().builtinType().objectidentifiertype() != null) {
					//printOID(ctx.IDENTIFIER(), va.value().builtinValue().objectIdentifierValue());
					createOID(ctx.IDENTIFIER(), va.value().builtinValue().objectIdentifierValue());
				}
			}
		}
	}

	private OID createOID(TerminalNode identifier, ObjectIdentifierValueContext oidCtx) {
		OID oid = OID.ROOT;
		for(ObjIdComponentsContext subid: oidCtx.objIdComponentsList().objIdComponents()) {
			if(subid.NUMBER() != null) {
				oid = oid.getChild(Integer.valueOf(subid.NUMBER().getText()));
			} else if(subid.IDENTIFIER() != null){
				oid = OID.getByName(subid.IDENTIFIER().getText());
			}
		}
		oid.setName(identifier.getText());
		return oid;
	}
		
	private void printOID(TerminalNode identifier, ObjectIdentifierValueContext oid) {
		System.out.print(identifier+" = ");
		for(ObjIdComponentsContext subid: oid.objIdComponentsList().objIdComponents()) {
			if(subid.NUMBER() != null) {
				System.out.print(subid.NUMBER().getText());
			} else if(subid.IDENTIFIER() != null){
				System.out.print(subid.IDENTIFIER().getText());
			} else {
				System.out.print('?');
			}
			System.out.print(' ');
		}
		System.out.println();
	}

	
}
