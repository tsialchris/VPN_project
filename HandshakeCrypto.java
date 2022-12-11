import java.security.Key;
//import java.security.PublicKey;
//import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.Cipher;


public class HandshakeCrypto {
	
	private Key key;
	private HandshakeCertificate handshakeCertificate;
	private KeyFactory keyFactory;
	//private PublicKey pub_key;
	//private PrivateKey priv_key;
	
	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		//System.out.println(Base64.getEncoder().encodeToString(handshakeCertificate.getCertificate().getPublicKey().getEncoded()));
		//key = new SessionKey(handshakeCertificate.getCertificate().getPublicKey().getEncoded());
		this.handshakeCertificate = handshakeCertificate;
		key = handshakeCertificate.getCertificate().getPublicKey();
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */

	public HandshakeCrypto(byte[] keybytes) {
		
		PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec(keybytes);
		try{
			keyFactory = KeyFactory.getInstance("RSA");
		}
		catch(Exception e){e.printStackTrace();}
		
		try{
			key = keyFactory.generatePrivate(key_spec);
		}
		catch(Exception e){e.printStackTrace();}
		
		
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) {
		try{
		//Create the Cipher
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
		//Initialize the Cipher
		cipher.init(Cipher.DECRYPT_MODE, key);
		
		//Add data to the cipher
		byte[] input = ciphertext;	  
		cipher.update(input);
		
		//Decrypting the data
		byte[] decipheredText = cipher.doFinal();
		
		return decipheredText;
		}
		catch(Exception e){e.printStackTrace();}
		
		return null;
    }

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) {
		try{
		//Create the Cipher
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
		//Initialize the Cipher
		cipher.init(Cipher.ENCRYPT_MODE, key);
		
		//Adding data to the cipher
		byte[] input = plaintext;	  
		cipher.update(input);
		
		//Encrypting the data
		byte[] cipherText = cipher.doFinal();
		
		return cipherText;
		}
		catch(Exception e){e.printStackTrace();}
		
		return null;
    }
}
