import java.security.MessageDigest;

public class HandshakeDigest {
	
	private MessageDigest message_digest;
	
    /*
     * Constructor -- initialise a digest for SHA-256
     */

    public HandshakeDigest() {
		try{
			message_digest = MessageDigest.getInstance("SHA-256");
		}
		catch(Exception e){}
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
		message_digest.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {
        return message_digest.digest();
    }
}
