package org.pvv.rolfn.asn1;

import static org.junit.Assert.*;

import java.io.IOException;

import org.antlr.v4.runtime.ANTLRFileStream;
import org.junit.Test;

public class ASN1ParserTest {

	@Test
	public void test() throws IOException {
		String classpathResource = "org/pvv/rolfn/asn1/oid.asn1";
		ASN1Parser.readASN1DefinitionsFromClasspath(classpathResource);
		
		//OID.prettyPrintKnownOIDTree();
	}

}
