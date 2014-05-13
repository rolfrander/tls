package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;
import org.pvv.rolfn.TestUtils;
import org.pvv.rolfn.tls.protocol.HandshakeTest;

public class ServerHelloTest extends HandshakeTest {

	public static final String TLS_SERVER_HELLO_HEX = "020000630303531a23118b832678e88d3e0b6ae1dcf93fec922c0be43b8316361d517b284c9e00c02b00003b00000000ff01000100000b000403000102002300003374002208737064792f34613408737064792f332e3106737064792f3308687474702f312e31";
	public static final String TLS_SERVER_RANDOM_HEX = "531a23118b832678e88d3e0b6ae1dcf93fec922c0be43b8316361d517b284c9e";
	
	@Test
	public void test() {
		// this implicitly updates security parameters in "params"
		HandshakeMessage msg = parseHandshake(TestUtils.hexToByteArray(TLS_SERVER_HELLO_HEX));
		byte[] random = ((ServerHello)msg).getRandom().getData();
		assertArrayEquals(TestUtils.hexToByteArray(TLS_SERVER_RANDOM_HEX), random);
	}

}
