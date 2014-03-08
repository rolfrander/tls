package org.pvv.rolfn.tls.protocol.record;

public enum Cipher {
	Null            (BulkCipherAlgorithm.Null,      null,              0,  0,  0), 
	rc4_128         (BulkCipherAlgorithm.rc4,       CipherType.stream, 16, 0,  0),
	threedes_ede_cbc(BulkCipherAlgorithm.three_des, CipherType.block,  24, 8,  8),
	aes_128_cbc     (BulkCipherAlgorithm.aes,       CipherType.block,  16, 16, 16),
	aes_256_cbc     (BulkCipherAlgorithm.aes,       CipherType.block,  32, 16, 16);
	
	private CipherType type;
	private BulkCipherAlgorithm bulk;
	private int keyLength;
	private int ivLength;
	private int blockSize;
	
	private Cipher(BulkCipherAlgorithm bulk, CipherType type, int keyLength, int ivLength, int blockSize) {
		this.bulk = bulk;
		this.type = type;
		this.keyLength = keyLength;
		this.ivLength = ivLength;
		this.blockSize = blockSize;
	}

	public CipherType getType() {
		return type;
	}

	public BulkCipherAlgorithm getBulk() {
		return bulk;
	}

	public int getKeyLength() {
		return keyLength;
	}

	public int getIvLength() {
		return ivLength;
	}

	public int getBlockSize() {
		return blockSize;
	}
	
	
}
