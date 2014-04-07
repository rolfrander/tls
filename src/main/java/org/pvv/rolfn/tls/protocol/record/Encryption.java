package org.pvv.rolfn.tls.protocol.record;

public interface Encryption {
	TLSCiphertext encrypt(TLSCompressed data);
	TLSCompressed decrypt(TLSCiphertext data);
}
