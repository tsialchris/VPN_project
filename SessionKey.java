import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;		//this will be used to generate the secret key, based on the bit length, that is provided (constructor #1)
import javax.crypto.spec.SecretKeySpec;	//import this, because it can be used to construct a secret key from a byte array (constructor #2)

/*
 * Skeleton code for class SessionKey
 */

class SessionKey {
	//this is our key
	private SecretKey sec_key;
	//
	
    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(int length) {
		//creating the KeyGenerator requires a try, catch
		try{
			//Create the KeyGenerator
			KeyGenerator KeyGen = KeyGenerator.getInstance("AES");
			//
			//Initializing the KeyGenerator with key length as input
			KeyGen.init(length);
			//generating and storing the key into sec_key
			sec_key = KeyGen.generateKey();
		}
		catch(Exception e){}
		
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
		//Use the keybytes provided, to create the sec_key
		sec_key = new SecretKeySpec(keybytes, "AES");
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return sec_key;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return sec_key.getEncoded();
    }
	
	//public String get_encoded_Key(){
	//	return Base64.getEncoder().encodeToString(this.sec_key.getEncoded());
	//}
}

