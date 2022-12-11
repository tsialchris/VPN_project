import java.net.*;
import java.io.*;
//be careful with this import, it might be needed in other places too...
import java.util.Base64;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.lang.Math;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

//private_server_cryptoknight uses the server's private key
//public_server_cryptoknight uses the server's public key
//public_client_cryptoknight uses the client's public key

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<path to user certificate>");
        System.err.println(indent + "--cacert=<path to CA certificate>");
        System.err.println(indent + "--key=<path to server's private key>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "user_certificate");
        arguments.setArgumentSpec("cacert", "CA_certificate");
        arguments.setArgumentSpec("key", "user_private_key");

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) {
        parseArgs(args);
        ServerSocket serverSocket = null;

        int port = Integer.parseInt(arguments.get("port"));
        String usercert_path = arguments.get("usercert");
        String cacert_path = arguments.get("cacert");
        String key_path = arguments.get("key");
		
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }
		
		//execute_handshake//
		
		HandshakeMessage handshake_message_1 = null;
		try{
			handshake_message_1 = handshake_message_1.recv(socket);
		}
		catch(Exception e){e.printStackTrace();}
		
		//1st step, receive the client certificate in String, convert it to HandshakeCertificate and verify it//
		String received_certificate_string = null;
		try{
			received_certificate_string = handshake_message_1.getParameter("Certificate");
		}
		catch(Exception e){e.printStackTrace();}
		
		byte[] received_certbytes = Base64.getDecoder().decode(received_certificate_string);
		
		HandshakeCertificate received_certificate = new HandshakeCertificate(received_certbytes);
		
		//verify the client certificate, with the help of the CA certificate//
		/* Read CA certificate from file and create HandshakeCertificate */
		FileInputStream instream = null;
		try{
			instream = new FileInputStream(cacert_path);
		}
		catch(Exception e){e.printStackTrace();}
		
        HandshakeCertificate cacert = new HandshakeCertificate(instream);
		try{
			received_certificate.verify(cacert);
		}
		catch(Exception e){e.printStackTrace();}
		//verify the client certificate, with the help of the CA certificate//
		
		//1st step, receive the client certificate in String, convert it to HandshakeCertificate and verify it//
		
		//2nd step, send the server certificate to the client//
		
		HandshakeCertificate handshake_usercert = null;
		byte[] certBytes1 = null;
		/* Read server certificate from file and create HandshakeCertificate */
		try{
			instream = new FileInputStream(usercert_path);
		}
		catch(Exception e){e.printStackTrace();}
		
		try{
			handshake_usercert = new HandshakeCertificate(instream);
		}
		catch(Exception e){e.printStackTrace();}
		
		certBytes1 = handshake_usercert.getBytes();
		
		//create the handshake_message and give it the parameters needed
		HandshakeMessage handshake_message_2 = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
		handshake_message_2.putParameter("Certificate", Base64.getEncoder().encodeToString(certBytes1));
		
		//wait for 0.2 second before sending this message
		try{
			Thread.sleep(200);
		}
		catch(Exception e){e.printStackTrace();}
		
		try{
			handshake_message_2.send(socket);
		}
		catch(Exception e){e.printStackTrace();}
		
		//2nd step, send the server certificate to the client//
		
		/*	3rd step, receive the encrypted session_key and IV,
			decrypt them using our private key and create the necessary objects
		*/
		
		HandshakeMessage handshake_message_3 = null;
		try{
			handshake_message_3 = handshake_message_3.recv(socket);
		}
		catch(Exception e){e.printStackTrace();}
		byte[] keybytes = null;
		//first we read our private key from the file that was provided//
		/* Read the key from file */
		try{
			instream = new FileInputStream(key_path);
		}
		catch(Exception e){e.printStackTrace();}
		
		try{
			keybytes = instream.readAllBytes();
		}
		catch(Exception e){e.printStackTrace();}
		//first we read our private key from the file that was provided//
		//create a de-crypter
        HandshakeCrypto private_server_cryptoknight = new HandshakeCrypto(keybytes);
		//read the received data//
		String encrypted_session_key_string = null;
		String encrypted_IV_string = null;
		try{
			encrypted_session_key_string = handshake_message_3.getParameter("SessionKey");
			encrypted_IV_string = handshake_message_3.getParameter("SessionIV");
		}
		catch(Exception e){e.printStackTrace();}
		
		byte[] encrypted_session_key = Base64.getDecoder().decode(encrypted_session_key_string);
		byte[] encrypted_session_IV = Base64.getDecoder().decode(encrypted_IV_string);
		//read the received data//
		
		//use the de-crypter to decrypt the session_key and the IV
		byte[] session_key_bytes = private_server_cryptoknight.decrypt(encrypted_session_key);
		byte[] session_IV_bytes = private_server_cryptoknight.decrypt(encrypted_session_IV);
		
		//create the SessionKey and SessionCipher objects//
		SessionKey sessionkey = new SessionKey(session_key_bytes);
		SessionCipher sessioncipher = new SessionCipher(sessionkey, session_IV_bytes);
		//create the SessionKey and SessionCipher objects//
		
		/*	3rd step, receive the encrypted session_key and IV,
			decrypt them using our private key and create the necessary objects
		*/
		
		//4th step, receive client's Signature (hash of all messages sent) and TimeStamp, then send our own//
		
		//get current TimeStamp
		Instant now = Instant.now();
		DateTimeFormatter TimeStamp = DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss");
		LocalDateTime localDateTime = LocalDateTime.ofInstant(now, ZoneId.systemDefault());
		
		//now receiving and then checking//
		
		HandshakeMessage handshake_message_4 = null;
		try{
			handshake_message_4 = handshake_message_4.recv(socket);
		}
		catch(Exception e){e.printStackTrace();}
		
		String received_signature_string = null;
		String received_timestamp_string = null;
		try{
			received_signature_string = handshake_message_4.getParameter("Signature");
			received_signature_string = handshake_message_4.getParameter("TimeStamp");
		}
		catch(Exception e){e.printStackTrace();}
		
		byte[] encrypted_received_sigbytes = Base64.getDecoder().decode(received_signature_string.getBytes());
		byte[] encrypted_received_timebytes = Base64.getDecoder().decode(received_signature_string.getBytes());
		//now we create the public_client_cryptoknight, that uses the client's public key to decrypt the data
		HandshakeCrypto public_client_cryptoknight = new HandshakeCrypto(received_certificate);
		byte[] received_sigbytes = public_client_cryptoknight.decrypt(encrypted_received_sigbytes);
		byte[] received_timebytes = public_client_cryptoknight.decrypt(encrypted_received_timebytes);
		
		//create a hash of the ServerHello message and compare it with the hash received now
		HandshakeDigest digest_1 = new HandshakeDigest();
		try{
			digest_1.update(handshake_message_2.getBytes());
		}
		catch(Exception e){e.printStackTrace();}
		byte[] final_digest_1 = digest_1.digest();
		
		if(Arrays.equals(final_digest_1, received_sigbytes)){
			System.out.println("Hashes match, proceeding with connection...");
		}
		else{
			System.out.println("Message digests don't match, exiting...");
			System.exit(1);
		}
		//byte[] to string for received_timebytes
		String TimeStamp_string_received = new String(received_timebytes);
		System.out.println("TimeStamp received: " + TimeStamp_string_received);
		//create a LocalDateTime from the received string and compare it with the LocalDateTime that we sent +/- 10ss
		LocalDateTime dateTime = LocalDateTime.parse(TimeStamp_string_received, TimeStamp);
		//compare dateTime (received) with localDateTime (sent)
		if(Math.abs(dateTime.compareTo(localDateTime)) < 10){
			System.out.println("TimeStamps within 10 seconds interval, proceeding...");
		}
		else{
			System.out.println("TimeStamps not within 10 seconds interval, exiting...");
			System.exit(1);
		}
		
		//done receiving and checking, now sending//
		
		//digest the client's messages and compate (ClientHello, SessionMessage)
		HandshakeDigest handshake_digest = new HandshakeDigest();
		try{
			handshake_digest.update(handshake_message_1.getBytes());
			handshake_digest.update(handshake_message_3.getBytes());
		}
		catch(Exception e){e.printStackTrace();}
		byte[] final_digest = handshake_digest.digest();
		
		//get a new current TimeStamp
		//Instant now = Instant.now();
		//localDateTime = LocalDateTime.ofInstant(now, ZoneId.systemDefault());
		ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(TimeStamp.format(localDateTime));
		
		byte[] encrypted_final_digest = private_server_cryptoknight.encrypt(final_digest);
		byte[] encrypted_TimeStamp = private_server_cryptoknight.encrypt(byteBuffer.array());
		
		HandshakeMessage handshake_message_5 = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
		
		handshake_message_5.putParameter("Signature", Base64.getEncoder().encodeToString(encrypted_final_digest));
		handshake_message_5.putParameter("TimeStamp", Base64.getEncoder().encodeToString(encrypted_TimeStamp));
		
		try{
			Thread.sleep(200);
		}
		catch(Exception e){e.printStackTrace();}
		
		try{
			handshake_message_5.send(socket);
		}
		catch(Exception e){e.printStackTrace();}
		
		//done sending//
		
		//4th step, receive client's Signature (hash of all messages sent) and TimeStamp, then send our own//
		
		//execute_handshake//
		
		//SWITCH to session mode//
		//encrypt the socket.getOutputStream
		CipherOutputStream encrypted_out = sessioncipher.openEncryptedOutputStream(System.out);
		
		//decrypt the socket.getInputStream
		CipherInputStream decrypted_in = sessioncipher.openDecryptedInputStream(System.in);
		
		//SWITCH to session mode//
		
		//forward traffic after the encryption//
		try {
            Forwarder.forwardStreams(decrypted_in, encrypted_out, socket.getInputStream(), socket.getOutputStream(), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
		//forward traffic after the encryption//
    }
}
