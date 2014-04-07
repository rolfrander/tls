package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public class ServerECDHParams {
	private ECParameters curve_params;
	private ECPoint _public;
	
	private ServerECDHParams() {
	}
	
	protected static ServerECDHParams read(ByteBuffer buf) {
		ServerECDHParams o = new ServerECDHParams();
		o.curve_params = ECParameters.read(buf);
		o._public = ECPoint.read(buf);
		return o;
	}
}
