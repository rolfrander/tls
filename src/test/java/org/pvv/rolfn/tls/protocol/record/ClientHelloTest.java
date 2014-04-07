package org.pvv.rolfn.tls.protocol.record;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.List;

import org.junit.Test;
import org.pvv.rolfn.TestUtils;

public class ClientHelloTest extends HandshakeTest {
	public static final String TLS_CLIENT_HELLO_HEX = //"010000a8"+
			"03033e3c130b79c86a12f263e642e4bd08f36966759e27bbe6d823f50d01be78e46300002ec02bc02fc00ac009c013c014c012c007c0110033003200450039003800880016002f004100350084000a00050004010000510000000f000d00000a676f6f676c652e636f6dff01000100000a00080006001700180019000b000201000023000033740000000500050100000000000d0012001004010501020104030503020304020202";
	public static final String TLS_CLIENT_RANDOM = "3e3c130b79c86a12f263e642e4bd08f36966759e27bbe6d823f50d01be78e463";
	
	@Test
	public void test() {
		byte[] byteData = TestUtils.hexToByteArray(TLS_CLIENT_HELLO_HEX);
		//HandshakeMessage msg = parseHandshake(byteData);
		//assertTrue(msg instanceof ClientHello);
		//ClientHello ch = (ClientHello)msg;
		ClientHello ch = ClientHello.read(ByteBuffer.wrap(byteData), byteData.length);
		assertEquals(ProtocolVersion.TLS1_2, ch.getClientVersion());
		assertArrayEquals(TestUtils.hexToByteArray(TLS_CLIENT_RANDOM), ch.getRandom().getData());
		
		ByteBuffer buf = ByteBuffer.allocate(byteData.length);
		ch.write(buf);
		
		assertArrayEquals(byteData, buf.array());
	}

}
