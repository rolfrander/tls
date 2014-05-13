package org.pvv.rolfn.asn1;

import java.io.IOException;
import java.io.InputStream;

import org.antlr.v4.runtime.ANTLRInputStream;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.ParseTreeWalker;
import org.pvv.rolfn.asn1.parser.ASNLexer;
import org.pvv.rolfn.asn1.parser.ASNListener;
import org.pvv.rolfn.asn1.parser.ASNParser;

public class ASN1Parser {

	public ASNParser readASN1DefinitionsFromClasspath(String classpathResource)
			throws IOException {
		InputStream stream = ASN1Parser.class.getClassLoader().getResource(classpathResource).openStream();
		CharStream input = new ANTLRInputStream(stream);
		ASNLexer lexer = new ASNLexer(input);
		CommonTokenStream tokens = new CommonTokenStream(lexer);
		ASNParser parser = new ASNParser(tokens);
		return parser;
	}

	public void walkParseTree(ParserRuleContext tree, ASNListener listen) {
		ParseTreeWalker walker = new ParseTreeWalker();
		walker.walk(listen,  tree);
	}

}
