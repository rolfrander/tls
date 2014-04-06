package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.util.*;

import org.pvv.rolfn.io.ByteBufferUtils;

public enum CipherSuite {
	TLS_RSA_WITH_AES_128_CBC_SHA(0x002F, KeyExchangeAlgorithm.rsa, Cipher.aes_128_cbc, MACAlgorithm.sha1),
	TLS_RSA_WITH_AES_128_CBC_SHA256(0x003c, KeyExchangeAlgorithm.rsa, Cipher.aes_128_cbc, MACAlgorithm.sha256),
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xc02b, KeyExchangeAlgorithm.ecdhe_ecdsa, Cipher.aes_128_gcm, MACAlgorithm.sha256);
	
	private int cipherSuite;
	private KeyExchangeAlgorithm keyExchange;
	private Cipher cipher;
	private MACAlgorithm mac;
	private int verifyDataLength = 0;
	private static Map<Integer,CipherSuite> suites;
	
	private CipherSuite(int id, KeyExchangeAlgorithm kx, Cipher cipher, MACAlgorithm mac) {
		cipherSuite = id;
		keyExchange = kx;
		this.cipher = cipher;
		this.mac = mac;
	}

	private CipherSuite(int id, KeyExchangeAlgorithm kx, Cipher cipher, MACAlgorithm mac, int verifyDataLength) {
		this(id, kx, cipher, mac);
		this.verifyDataLength = verifyDataLength;
	}
	
	synchronized private static Map<Integer,CipherSuite> getSuites() {
		if(suites == null) {
			suites = new TreeMap<Integer,CipherSuite>();
			for(CipherSuite c: CipherSuite.values()) {
				suites.put(c.cipherSuite, c);
			}
		}
		return suites;
	}
	
	public static CipherSuite fromId(int id) {
		if(suites == null) {
			getSuites();
		}
		return suites.get(id);
	}
	
	protected static CipherSuite read(ByteBuffer buf) {
		return fromId(ByteBufferUtils.getUnsignedShort(buf));
	}
	
	public int getId() {
		return cipherSuite;
	}
	
	public int getCipherSuite() {
		return cipherSuite;
	}

	public Cipher getCipher() {
		return cipher;
	}

	public MACAlgorithm getMac() {
		return mac;
	}

	public int getVerifyDataLength() {
		return verifyDataLength;
	}

	public KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
		return keyExchange;
	}
	
	public String toString() {
		return String.format("0x%04x %s", cipherSuite, this.name());
	}
}
