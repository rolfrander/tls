package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.TreeMap;

import org.pvv.rolfn.io.ByteBufferUtils;

public enum AlertDescription {
    close_notify(0),
    unexpected_message(10),
    bad_record_mac(20),
    decryption_failed_RESERVED(21),
    record_overflow(22),
    decompression_failure(30),
    handshake_failure(40),
    no_certificate_RESERVED(41),
    bad_certificate(42),
    unsupported_certificate(43),
    certificate_revoked(44),
    certificate_expired(45),
    certificate_unknown(46),
    illegal_parameter(47),
    unknown_ca(48),
    access_denied(49),
    decode_error(50),
    decrypt_error(51),
    export_restriction_RESERVED(60),
    protocol_version(70),
    insufficient_security(71),
    internal_error(80),
    user_canceled(90),
    no_renegotiation(100),
    unsupported_extension(110);
    
	private int id;
	private static Map<Integer, AlertDescription> alerts;

	private AlertDescription(int id) {
		this.id = id;
	}
	
	protected static AlertDescription read(ByteBuffer buf) {
		return fromId(ByteBufferUtils.getUnsignedByte(buf));
	}

	synchronized private static Map<Integer,AlertDescription> getAlerts() {
		if(alerts == null) {
			alerts = new TreeMap<Integer,AlertDescription>();
			for(AlertDescription ad: AlertDescription.values()) {
				alerts.put(ad.id, ad);
			}
		}
		return alerts;
	}
	
	public static AlertDescription fromId(int id) {
		if(alerts == null) {
			getAlerts();
		}
		return alerts.get(id);
	}

}
