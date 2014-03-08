package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

public enum ClientCertificateType {
	rsa_sign(1), 
	dss_sign(2), 
	rsa_fixed_dh(3), 
	dss_fixed_dh(4),
    rsa_ephemeral_dh(5), 
    dss_ephemeral_dh(6),
    fortezza_dms(20);
	
	private int id;

	private ClientCertificateType(int id) {
		this.id = id;
	}
	
	public static ClientCertificateType read(ByteBuffer buf) {
		return fromId(RecordUtils.getUnsignedByte(buf));
	}
	
	public static ClientCertificateType fromId(int id) {
		switch(id) {
		case 1: return rsa_sign;
		case 2: return dss_sign;
		case 3: return rsa_fixed_dh;
		case 4: return dss_fixed_dh;		
		case 5: return rsa_ephemeral_dh;
		case 6: return dss_ephemeral_dh;
		case 20:return fortezza_dms;
		default: return null;
		}
	}
}
