package org.pvv.rolfn.tls.protocol.record;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.pvv.rolfn.io.ByteBufferUtils;

public class ServerDHParams implements DHPublicKey {
	private static final long serialVersionUID = -1278475975986448052L;
	private byte dh_p[];
	private byte dh_g[];
	private byte dh_Ys[];
	private BigInteger p;
	private BigInteger g;
	private BigInteger Y;
	
	private ServerDHParams(ByteBuffer buf) {
		dh_p = ByteBufferUtils.readArray16(buf);
		dh_g = ByteBufferUtils.readArray16(buf);
		dh_Ys = ByteBufferUtils.readArray16(buf);
		p = new BigInteger(1, dh_p);
		g = new BigInteger(1, dh_g);
		Y = new BigInteger(1, dh_Ys);
	}
	
	static protected ServerDHParams read(ByteBuffer buf) {
		return new ServerDHParams(buf);
	}
	
	@Override
	public DHParameterSpec getParams() {
		return new DHParameterSpec(p, g);
	}

	@Override
	public String getAlgorithm() {
		return "DH";
	}

	@Override
	public String getFormat() {
		return "X.509";
	}

	@Override
	public byte[] getEncoded() {
		throw new RuntimeException("not implemented");
	}

	@Override
	public BigInteger getY() {
		return Y;
	}
}