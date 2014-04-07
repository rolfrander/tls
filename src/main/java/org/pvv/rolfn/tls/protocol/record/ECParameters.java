package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

import org.pvv.rolfn.io.ByteBufferUtils;

public class ECParameters {
	/**
	 * This identifies the type of the elliptic curve domain parameters.
	 */
	private ECCurveType curve_type;

	private byte[] prime_p;
	private ECCurve curve;
	private ECPoint base;
	private byte[] order;
	private byte[] cofactor;

	private int m;
	private ECBasisType basis;
	private byte[] k;
	private byte[] k1;
	private byte[] k2;
	private byte[] k3;

	/**
	 * Specifies a recommended set of elliptic curve domain parameters. All
	 * those values of NamedCurve are allowed that refer to a specific curve.
	 * Values of NamedCurve that indicate support for a class of explicitly
	 * defined curves are not allowed here (they are only permissible in the
	 * ClientHello extension); this applies to
	 * arbitrary_explicit_prime_curves(0xFF01) and
	 * arbitrary_explicit_char2_curves(0xFF02).
	 */
	private NamedCurve named_curve;

	private ECParameters(ByteBuffer buf) {
		curve_type = ECCurveType.read(buf);
		switch (curve_type) {
		case explicit_prime:
			prime_p = ByteBufferUtils.readArray8(buf);
			curve = ECCurve.read(buf);
			base = ECPoint.read(buf);
			order = ByteBufferUtils.readArray8(buf);
			cofactor = ByteBufferUtils.readArray8(buf);
			break;

		case explicit_char2:
			m = ByteBufferUtils.getUnsignedShort(buf);
			basis = ECBasisType.read(buf);
			switch (basis) {
			case ec_basis_trinomial:
				k = ByteBufferUtils.readArray8(buf);
				break;
			case ec_basis_pentanomial:
				k1 = ByteBufferUtils.readArray8(buf);
				k2 = ByteBufferUtils.readArray8(buf);
				k3 = ByteBufferUtils.readArray8(buf);
			}
			curve = ECCurve.read(buf);
			base = ECPoint.read(buf);
			order = ByteBufferUtils.readArray8(buf);
			cofactor = ByteBufferUtils.readArray8(buf);
			break;

		case named_curve:
			named_curve = NamedCurve.read(buf);
			break;
		}
	}

	protected static ECParameters read(ByteBuffer buf) {
		return new ECParameters(buf);
	}
}
