package org.pvv.rolfn.tls.protocol.record;

public enum Cipher {
	Null            (BulkCipherAlgorithm.Null,      null,              0,  0,  0), 
	rc4_128         (BulkCipherAlgorithm.rc4,       CipherType.stream, 16, 0,  0),
	threedes_ede_cbc(BulkCipherAlgorithm.three_des, CipherType.block,  24, 8,  8),
	aes_128_cbc     (BulkCipherAlgorithm.aes,       CipherType.block,  16, 16, 16),
	aes_256_cbc     (BulkCipherAlgorithm.aes,       CipherType.block,  32, 16, 16),
	aes_128_gcm     (BulkCipherAlgorithm.aes,       CipherType.aead,   16, 16, 16),
	aes_256_gcm     (BulkCipherAlgorithm.aes,       CipherType.aead,  32, 16, 16),
	
	// not completely defined
	aes_128_ccm (BulkCipherAlgorithm.aes, CipherType.aead, 0, 0, 0),
	aes_128_ccm_8 (BulkCipherAlgorithm.aes, CipherType.aead, 0, 0, 0),
	aes_256_ccm (BulkCipherAlgorithm.aes, CipherType.aead, 0, 0, 0),
	aes_256_ccm_8 (BulkCipherAlgorithm.aes, CipherType.aead, 0, 0, 0),
	aria_128_cbc (BulkCipherAlgorithm.aria, CipherType.block, 0, 0, 0),
	aria_128_gcm (BulkCipherAlgorithm.aria, CipherType.aead, 0, 0, 0),
	aria_256_cbc (BulkCipherAlgorithm.aria, CipherType.block, 0, 0, 0),
	aria_256_gcm (BulkCipherAlgorithm.aria, CipherType.aead, 0, 0, 0),
	camellia_128_cbc (BulkCipherAlgorithm.camellia, CipherType.block, 0, 0, 0),
	camellia_128_gcm (BulkCipherAlgorithm.camellia, CipherType.aead, 0, 0, 0),
	camellia_256_cbc (BulkCipherAlgorithm.camellia, CipherType.block, 0, 0, 0),
	camellia_256_gcm (BulkCipherAlgorithm.camellia, CipherType.aead, 0, 0, 0),
	des_cbc (BulkCipherAlgorithm.des, CipherType.block, 0, 0, 0),
	des_cbc_40 (BulkCipherAlgorithm.des, CipherType.block, 0, 0, 0),
	des40_cbc (BulkCipherAlgorithm.des, CipherType.block, 0, 0, 0),
	idea_cbc (BulkCipherAlgorithm.idea, CipherType.block, 0, 0, 0),
	rc2_cbc_40 (BulkCipherAlgorithm.rc2, CipherType.block, 0, 0, 0),
	rc4_40 (BulkCipherAlgorithm.rc4, CipherType.stream, 0, 0, 0),
	seed_cbc (BulkCipherAlgorithm.seed, CipherType.block, 0, 0, 0);

	
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
