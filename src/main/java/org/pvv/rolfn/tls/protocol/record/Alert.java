package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;

/**
 *   One of the content types supported by the TLS record layer is the
 *   alert type.  Alert messages convey the severity of the message
 *   (warning or fatal) and a description of the alert.  Alert messages
 *   with a level of fatal result in the immediate termination of the
 *   connection.  In this case, other connections corresponding to the
 *   session may continue, but the session identifier MUST be invalidated,
 *   preventing the failed session from being used to establish new
 *   connections.  Like other messages, alert messages are encrypted and
 *   compressed, as specified by the current connection state.
 *   
 * @author RolfRander
 *
 */
public class Alert {
	private AlertLevel level;
	private AlertDescription description;
	
	private Alert(ByteBuffer buf) {
		level = AlertLevel.read(buf);
		description = AlertDescription.read(buf);
	}
	
	static protected Alert read(ByteBuffer buf) {
		return new Alert(buf);
	}
	
	static public Alert read(TLSPlaintext msg) {
		if(msg.getContentType() != ContentType.alert) {
			throw new IllegalArgumentException("not an alert: "+msg.getContentType());
		}
		return read(ByteBuffer.wrap(msg.getData()));
	}
	
	@Override
	public String toString() {
		return "Alert ["+level+"]: "+description;
	}
}
