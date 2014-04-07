package org.pvv.rolfn.tls.protocol.record;

public enum HandshakeType {
	hello_request(0),
	client_hello(1),
	server_hello(2),
	certificate(11),
	server_key_exchange (12),
	certificate_request(13), 
	server_hello_done(14),
	certificate_verify(15),
	client_key_exchange(16),
	finished(20);
	
	private int id;
	
	private HandshakeType(int id) {
		this.id = id;
	}
	
	static protected HandshakeType byid(int id) {
		switch(id) {
		case 0: return hello_request;
		case 1: return client_hello;
		case 2: return server_hello;
		case 11: return certificate;
		case 12: return server_key_exchange;
		case 13: return certificate_request;
		case 14: return server_hello_done;
		case 15: return certificate_verify;
		case 16: return client_key_exchange;
		case 20: return finished;
		default: return null;
		}
	}
}