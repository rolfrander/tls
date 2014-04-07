package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;
import org.pvv.rolfn.TestUtils;

public class CertificateVerifyTest {

	public static final String CERTIFICATE_VERIFY = "020101002e2eced826a3486e34e2d857653ea9ebe6313887756aa400804aed0b4016ffc287d97676a3822ec9b8d8a2eed31b80dcdd70ec6d31978e624e097bf616e92f38ea1879648ee93b2fd84bdad1cb00006effae868138a063789fee51f70f93bf33a037f4a1ad6bab35a6e9fb03a50fa4eeee9e7709fe0f09233e2a07c4d1fd5df5da09706e9499403664e0d3077c31273655b27cf78eece846299423158556731d97601e8136c1e268b8a8863037445260bd18615c015db77c65cda710bd8a0e6f0e7ff182df04f53504c8f834616bbcf7221919837baf9002c5eee7bebf004d5f67a5cd20e3508a228379fc42b54830d517f8967ae0f146e7a15ab126a1813718";
	
	@Test
	public void test() {
		CertificateVerify cv = new CertificateVerify(ByteBuffer.wrap(TestUtils.hexToByteArray(CERTIFICATE_VERIFY)));
		
		DigitallySigned sign = cv.getSignature();
		assertEquals(HashAlgorithm.sha1, sign.getAlgo().getHashAlgorithm());
		assertEquals(SignatureAlgorithm.rsa, sign.getAlgo().getSignatureAlgorithm());
	}

}
