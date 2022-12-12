import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.Principal;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.PublicKey;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
//import javax.security.cert.X509Certificate;
//import javax.security.auth.x500.X500Principal;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {
	
	private X509Certificate cert;
	
    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) {
		try{
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate)certFactory.generateCertificate(instream);
		}
		catch(Exception e){}
		//try{
		//	cert = X509Certificate.getInstance(instream);
		//}
		//catch(Exception e){}
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) {
		try{
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream instream = new ByteArrayInputStream(certbytes);
			cert = (X509Certificate)certFactory.generateCertificate(instream);
		}
		catch(Exception e){}
		//try{
		//	cert = X509Certificate.getInstance(certbytes);
		//}
		//catch(Exception e){}
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() {
		try{
			return cert.getEncoded();
		}
		catch(Exception e){}
		return null;
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return cert;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
		//try{
		cacert.getCertificate().checkValidity();
		
		PublicKey public_key = cacert.getCertificate().getPublicKey();
		
		cacert.getCertificate().verify(public_key);
		//}
		//catch(Exception e){}
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
		String temp;
		String CN;
		
		//temp = cert.getSubjectX500Principal().getName();
		temp = cert.getSubjectX500Principal().toString();
		
		char[] CN_char = new char[temp.length()];
		int i = 0;
		int j = 0;
		boolean found_CN = false;
		//boolean found_CN_end = false;
		//boolean found_C = false;
		//int counter = 0;
		//System.out.println(temp);
		//try{
			while(true){
				
				if(temp.charAt(i) == 'C'){
					if(temp.charAt(i+1) == 'N'){
						if(temp.charAt(i+2) == '='){
							i = i + 3;
							found_CN = true;
						}
					}
				}
				if(found_CN & temp.charAt(i) == ','){
					break;
				}
				if(found_CN){
					CN_char[j] = temp.charAt(i);
					j = j + 1;
				}
				
				i = i + 1;
			}
		//}
		//catch(Exception e){}
		
		//trim the CN_char[] array
		//calculate the actual length
		i = 0;
		while(CN_char[i] != '\0'){
			//System.out.println(CN_char[i]);
			i = i + 1;
		}
		//i is now the length of the trimmed array
		
		char[] CN_char_trimmed = new char[i];
		
		j = 0;
		while(j < i){
			CN_char_trimmed[j] = CN_char[j];
			j = j + 1;
		}
		
		//trim the CN_char[] array
		
		CN = new String(CN_char_trimmed);
		//CN.trim();
		return CN;
    }

    /*
     * return email address of subject
     */
    public String getEmail() {
        String temp;
		String mail;
		
		//temp = cert.getSubjectX500Principal().getName();
		temp = cert.getSubjectX500Principal().toString();
		
		char[] mail_char = new char[temp.length()];
		int i = 0;
		int j = 0;
		boolean found_mail = false;
		
		try{
			while(true){
				//EMAILADDRESS=
				if(temp.charAt(i) == 'E'){
					if(temp.charAt(i+1) == 'M'){
						if(temp.charAt(i+2) == 'A'){
							if(temp.charAt(i+3) == 'I'){
								if(temp.charAt(i+4) == 'L'){
									if(temp.charAt(i+5) == 'A'){
										if(temp.charAt(i+6) == 'D'){
											if(temp.charAt(i+7) == 'D'){
												if(temp.charAt(i+8) == 'R'){
													if(temp.charAt(i+9) == 'E'){
														if(temp.charAt(i+10) == 'S'){
															if(temp.charAt(i+11) == 'S'){
																if(temp.charAt(i+12) == '='){
																	i = i + 13;
																	found_mail = true;
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
				if(found_mail & temp.charAt(i) == ','){
					break;
				}
				if(found_mail){
					mail_char[j] = temp.charAt(i);
					j = j + 1;
				}
				
				i = i + 1;
			}
		}
		catch(Exception e){}
		
		//trim the mail_char[] array
		//calculate the actual length
		i = 0;
		while(mail_char[i] != '\0'){
			//System.out.println(mail_char[i]);
			i = i + 1;
		}
		//i is now the length of the trimmed array
		
		char[] mail_char_trimmed = new char[i];
		
		j = 0;
		while(j < i){
			mail_char_trimmed[j] = mail_char[j];
			j = j + 1;
		}
		
		//trim the mail_char[] array
		//System.out.println("OK OUT");
		mail = new String(mail_char_trimmed);
		//mail.trim();
		return mail;
    }
}
