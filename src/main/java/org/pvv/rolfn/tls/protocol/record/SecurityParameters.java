package org.pvv.rolfn.tls.protocol.record;

public class SecurityParameters {
	// all short values are really uint8
	
	private ConnectionEnd entity;
	private PRFAlgorithm  prfAlgorithm;
	private int           fixedIvLength;
	private short         compressionAlgorithm;
	private byte          masterSecret[];
	private Random        clientRandom;
	private Random        serverRandom;
	private CipherSuite   cipherSuite;
	private Certificate   clientCertificate;
	private Certificate   serverCertificate;
	
	public ConnectionEnd getEntity() {
		return entity;
	}
	public void setEntity(ConnectionEnd entity) {
		this.entity = entity;
	}
	public PRFAlgorithm getPrfAlgorithm() {
		return prfAlgorithm;
	}
	public void setPrfAlgorithm(PRFAlgorithm prfAlgorithm) {
		this.prfAlgorithm = prfAlgorithm;
	}
	public CipherSuite getCipherSuite() {
		return cipherSuite;
	}
	public void setCipherSuite(CipherSuite cipher) {
		this.cipherSuite = cipher;
	}
	public BulkCipherAlgorithm getBulkCipherAlgorithm() {
		return cipherSuite.getCipher().getBulk();
	}
	public CipherType getCipherType() {
		return cipherSuite.getCipher().getType();
	}
	public int getEncKeyLength() {
		return cipherSuite.getCipher().getKeyLength();
	}
	public int getBlockLength() {
		return cipherSuite.getCipher().getBlockSize();
	}
	public int getFixedIvLength() {
		return fixedIvLength;
	}
	public void setFixedIvLength(int fixedIvLength) {
		this.fixedIvLength = fixedIvLength;
	}
	public int getRecordIvLength() {
		return cipherSuite.getCipher().getIvLength();
	}
	public MACAlgorithm getMacAlgorithm() {
		return cipherSuite.getMac();
	}
	public int getMacLength() {
		return cipherSuite.getMac().getLength();
	}
	public int getMacKeyLength() {
		return cipherSuite.getMac().getKeyLength();
	}
	public short getCompressionAlgorithm() {
		return compressionAlgorithm;
	}
	public void setCompressionAlgorithm(short compressionAlgorithm) {
		this.compressionAlgorithm = compressionAlgorithm;
	}
	public byte[] getMasterSecret() {
		return masterSecret;
	}
	public void setMasterSecret(byte[] masterSecret) {
		this.masterSecret = masterSecret;
	}
	public Random getClientRandom() {
		return clientRandom;
	}
	public void setClientRandom(Random clientRandom) {
		this.clientRandom = clientRandom;
	}
	public Random getServerRandom() {
		return serverRandom;
	}
	public void setServerRandom(Random serverRandom) {
		this.serverRandom = serverRandom;
	}
	public Certificate getClientCertificate() {
		return this.clientCertificate;
	}
	public void setClientCertificate(Certificate certificate) {
		this.clientCertificate = certificate;
	}	
	public Certificate getServerCertificate() {
		return this.serverCertificate;
	}
	public void setServerCertificate(Certificate certificate) {
		this.serverCertificate = certificate;
	}
}
