package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.List;

import org.junit.Test;
import org.pvv.rolfn.TestUtils;

public class ClientKeyExchangeTest extends HandshakeTest {

	public static final String CLIENT_KEY_EXCHANGE = "10000102010085797cb5f3b3a73b12ecb6c4aa8a1f0320ba4ea9442adc5405e87d5c8be39f77"
			+ "fe007ed0ee1a320e860f7f893b55daa195ad9e96a4930d9832fd7520f2ae52dec6fa4e784f112281e779dcef5f6003e111381913807921c59fd"
			+ "1df033e9a4d966aff7107f785a2acad902477bd20f490fe28f097e208605a9c3d2c750ae98ee27424b0bf3abc7d5dacde7382a314e024c16673"
			+ "e4388188f0735fe0c0ef89076bfe9e4e97b0af7dde8c12a9a2a45d2d3bc3b2e05aceb1dcd946372d41a77616a083d1a0beafbd0d79d1963a14f"
			+ "3655972f6416c5199ba99cde18bff53533ae9ce8c966c5af6e5fb0628bf17d7bd6a4e508e51c91289362eca14d5a128be6f3780";
	
	@Test
	public void test() {
		params.setCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
		HandshakeMessage message = parseHandshake(TestUtils.hexToByteArray(CLIENT_KEY_EXCHANGE));
		
		assertTrue(message instanceof ClientKeyExchange);
		
		ClientKeyExchange cke = (ClientKeyExchange)message;
		assertNotNull(cke.getEpms());
		assertNull(cke.getClientDHpub());
		assertEquals(256, cke.getEpms().getData().length);
	}

}
