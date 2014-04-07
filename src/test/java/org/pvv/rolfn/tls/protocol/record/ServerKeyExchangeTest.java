package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;
import org.pvv.rolfn.TestUtils;

public class ServerKeyExchangeTest extends HandshakeTest{
	public final static String TLS_SKX_ECC_HEX = "0c00009003001741042763c58903d3edb18427deb6da919faca10849f8199c10fc55f220c6564c295c9ca293b37ddb3d0b609a259a09d62c705cd551500a062c269943458f4a4dfe3a040300473045022068b0a94928de7533f8fff3b7f487a967a795713d2f6cc5fa6f436f73ef680ea5022100dd143a82b4c402d0e20a691de804ea0883ef41a77e4ede6083d3b065c86e67ea";

	@Test
	public void test() {
		params.setEntity(ConnectionEnd.client);
		params.setCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
		HandshakeMessage msg = parseHandshake(TestUtils.hexToByteArray(TLS_SKX_ECC_HEX));
		assertTrue(msg instanceof ServerKeyExchange);
		assertNotNull("no ecdh parameters", ((ServerKeyExchange)msg).getEcdhParams());
	}

}
