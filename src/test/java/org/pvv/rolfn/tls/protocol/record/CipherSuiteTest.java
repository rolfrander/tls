package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;

public class CipherSuiteTest {

	private ByteBuffer twoBytes(int a, int b) {
		return ByteBuffer.wrap(new byte[] { (byte)a, (byte)b } );		
	}
	
	private CipherSuite getCipher(int high, int low) {
		return CipherSuite.read(twoBytes(high, low));
	}
	
	@Test
	public void test() {
		assertEquals(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, getCipher(0x00, 0x2f));
	}

}
