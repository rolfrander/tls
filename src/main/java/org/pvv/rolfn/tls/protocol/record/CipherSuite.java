package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.util.*;

public enum CipherSuite {
	TLS_RSA_WITH_AES_128_CBC_SHA(0x002F, KeyExchangeAlgorithm.rsa, Cipher.aes_128_cbc, MACAlgorithm.sha1);
	
	
	private int cipherSuite;
	private KeyExchangeAlgorithm keyExchange;
	private Cipher cipher;
	private MACAlgorithm mac;
	private static Map<Integer,CipherSuite> suites;
	
	private CipherSuite(int id, KeyExchangeAlgorithm kx, Cipher cipher, MACAlgorithm mac) {
		cipherSuite = id;
		keyExchange = kx;
		this.cipher = cipher;
		this.mac = mac;
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
	
	public static CipherSuite read(ByteBuffer buf) {
		return fromId(buf.getShort() & 0xffff);
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

	public KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
		return keyExchange;
	}
	
	public String toString() {
		return String.format("0x%04x %s", cipherSuite, this.name());
	}
}
