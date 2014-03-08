package org.pvv.rolfn.tls.protocol.record;

public enum ContentType {
	change_cipher_spec(20),
	alert(21),
	handshake(22),
    application_data(23);
	
	private int id;

	private ContentType(int id) {
		this.id = id;
	}
	
	static public ContentType byid(int id) {
		switch(id) {
		case 20: return change_cipher_spec;
		case 21: return alert;
		case 22: return handshake;
		case 23: return application_data;
		default: return null;
		}
	}
	
	public int getId() {
		return id;
	}
}