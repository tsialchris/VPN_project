import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

import javax.crypto.spec.IvParameterSpec;	//need this to generate the initial_vector
import java.security.SecureRandom;			//a secure source of randomness

public class SessionCipher {
	//46-48 fjalraven
	private byte[] ivbytes;
	private SessionKey key;
	private CipherOutputStream out_stream;
	private CipherInputStream in_stream;
	private IvParameterSpec iv_spec;
	private Cipher cipher1;
	private Cipher cipher2;
	
    /*
     * Constructor to create a SessionCipher from a SessionKey. The Initial Vector is
     * created automatically.
     */
    public SessionCipher(SessionKey key) {
		ivbytes = new byte[128 / 8];	// 128div8 equals 128 bits
		//generate the initial_vector
	    new SecureRandom().nextBytes(ivbytes);
	    iv_spec = new IvParameterSpec(ivbytes);
		
		//Key stuff
		this.key = key;
		
		//creating the ciphers, based on the instructions of the assignment
		try{
			cipher1 = Cipher.getInstance("AES/CTR/NoPadding");
			cipher1.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), iv_spec);
			cipher2 = Cipher.getInstance("AES/CTR/NoPadding");
			cipher2.init(Cipher.DECRYPT_MODE, key.getSecretKey(), iv_spec);
		}
		catch(Exception e){e.printStackTrace();}
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an Initial Vector,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) {
		//ivbytes = new byte[128 / 8];	// 128div8 equals 128 bits
		//create the iv_spec, based on the provided bytes
		this.ivbytes = ivbytes;
		iv_spec = new IvParameterSpec(ivbytes);
		
		//Key stuff
		this.key = key;
		
		//creating the ciphers, based on the instructions of the assignment
		try{
			cipher1 = Cipher.getInstance("AES/CTR/NoPadding");
			cipher1.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), iv_spec);
			cipher2 = Cipher.getInstance("AES/CTR/NoPadding");
			cipher2.init(Cipher.DECRYPT_MODE, key.getSecretKey(), iv_spec);
		}
		catch(Exception e){e.printStackTrace();}
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return key;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return ivbytes;
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) {
		//
		//creating the CipherOutputStream, based on the input
		try{
			out_stream = new CipherOutputStream(os, cipher1);
		}
		catch(Exception e){e.printStackTrace();}
		//
        return out_stream;
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) {
		//
		//creating the CipherInputStream, based on the input
		try{
			in_stream = new CipherInputStream(inputstream, cipher2);
		}
		catch(Exception e){e.printStackTrace();}
		//
        return in_stream;
    }
}
