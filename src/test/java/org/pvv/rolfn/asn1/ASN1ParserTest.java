package org.pvv.rolfn.asn1;

import static org.junit.Assert.*;

import java.io.IOException;

import org.antlr.v4.runtime.ANTLRErrorStrategy;
import org.antlr.v4.runtime.Parser;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.tree.ErrorNode;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.ParseTreeListener;
import org.antlr.v4.runtime.tree.TerminalNode;
import org.junit.Test;
import org.pvv.rolfn.asn1.parser.ASNParser;

public class ASN1ParserTest {

	ASN1Parser parser = new ASN1Parser();
	
	@Test
	public void test() throws IOException {
		//parse("org/pvv/rolfn/asn1/oid.asn1");
		//parse("org/pvv/rolfn/x509/PKIX1Algorithms88.asn1");
		parse("org/pvv/rolfn/x509/PKIX1-PSS-OAEP-Algorithms.asn1");
		//parse("org/pvv/rolfn/x509/PKIX1Explicit88.asn1");
		
		//OID.prettyPrintKnownOIDTree();
	}

	public void parse(String file) throws IOException {
		System.out.println(file);
		final ASNParser p = parser.readASN1DefinitionsFromClasspath(file);
		p.addParseListener(new ParseTreeListener() {
			int indent = 0;
			private static final String SPACE="                                                                                                                                               ";
			@Override
			public void visitTerminal(TerminalNode node) {
				/*
				System.out.print(SPACE.subSequence(0, indent));
				System.out.println("visit "+node);
				*/
			}
			
			@Override
			public void visitErrorNode(ErrorNode node) {
				/*
				 */
				System.out.print(SPACE.subSequence(0, indent));
				ParseTree parent = node.getParent();
				System.out.println("ERROR "+parent);
				if(parent instanceof ParserRuleContext) {
					System.out.println("      "+((ParserRuleContext)parent).toInfoString(p));
				}
			}
			
			@Override
			public void enterEveryRule(ParserRuleContext ctx) {
				/*
				System.out.print(SPACE.subSequence(0, indent));
				System.out.println("enter "+ctx.toInfoString(p));
				indent++;
				 */
			}

			@Override
			public void exitEveryRule(ParserRuleContext ctx) {
				/*
				indent--;
				System.out.print(SPACE.subSequence(0, indent));
				System.out.println("exit "+ctx.getPayload());
				*/
			}
			
		});
		parser.walkParseTree(p.moduleDefinition(), new OIDListener());
	}

}
