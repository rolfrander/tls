package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class Finished implements HandshakeMessage {

	public static final String FINISHED_LABEL_CLIENT = "client finished";
	public static final String FINISHED_LABEL_SERVER = "server finished";
	public static final int verify_data_length = 12;
	
	private byte[] verifyData;
	
	public Finished(ByteBuffer buf) {
		verifyData = new byte[verify_data_length];
		buf.get(verifyData);
	}

}
