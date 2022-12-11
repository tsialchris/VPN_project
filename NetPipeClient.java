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

//private_client_cryptoknight uses the client's private key
//public_server_cryptoknight uses the server's public key
//public_client_cryptoknight uses the client's public key

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<path to user certificate>");
        System.err.println(indent + "--cacert=<path to CA certificate>");
        System.err.println(indent + "--key=<path to user's private key>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
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
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) {
        Socket socket = null;
		
        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
		String usercert_path = arguments.get("usercert");
		String cacert_path = arguments.get("cacert");
		String key_path = arguments.get("key");
		
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }
		
		//execute_handshake//
		
		//find the client's certificate and create an object based on the given path, then extract its bytes//
		HandshakeCertificate handshake_usercert = null;
		FileInputStream instream = null;
		byte[] certBytes1 = null;
		/* Read user certificate from file and create HandshakeCertificate */
		try{
			instream = new FileInputStream(usercert_path);
		}
		catch(Exception e){e.printStackTrace();}
		
		try{
			handshake_usercert = new HandshakeCertificate(instream);
		}
		catch(Exception e){e.printStackTrace();}
		
		certBytes1 = handshake_usercert.getBytes();
		
		//find the client's certificate and create an object based on the given path, then extract its bytes//
		
		//1st step, send the ClientHello message (send client certificate to server//
		//create the handshake_message and give it the parameters needed
		HandshakeMessage handshake_message_1 = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
		handshake_message_1.putParameter("Certificate", Base64.getEncoder().encodeToString(certBytes1));
		
		//wait for 0.2 second before sending this message
		try{
			Thread.sleep(200);
		}
		catch(Exception e){e.printStackTrace();}
		
		try{
			handshake_message_1.send(socket);
		}
		catch(Exception e){e.printStackTrace();}
		//1st step, send the ClientHello message (send client certificate to server//
		
		//2nd step, wait for response from the server and validate the server certificate//
		
		HandshakeMessage handshake_message_2 = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
		try{
			handshake_message_2 = handshake_message_2.recv(socket);
		}
		catch(Exception e){e.printStackTrace();}
		
		String received_certificate_string = null;
		try{
			received_certificate_string = handshake_message_2.getParameter("Certificate");
		}
		catch(Exception e){e.printStackTrace();}
		
		byte[] received_certbytes = received_certificate_string.getBytes();
		
		HandshakeCertificate received_certificate = new HandshakeCertificate(received_certbytes);
		
		//verify the server certificate, with the help of the CA certificate//
		/* Read CA certificate from file and create HandshakeCertificate */
		try{
			instream = new FileInputStream(cacert_path);
		}
		catch(Exception e){e.printStackTrace();}
		
        HandshakeCertificate cacert = new HandshakeCertificate(instream);
		try{
			received_certificate.verify(cacert);
		}
		catch(Exception e){e.printStackTrace();}
		//verify the server certificate, with the help of the CA certificate//
		
		//2nd step, wait for response from the server and validate the server certificate//
		
		/*	3rd step, create the AES sessionkey and the sessioncipher (IV to be sent),
			then encrypt them with the Server's public key
			and send them to the server
		*/
		
		SessionKey sessionkey = new SessionKey(128);
		SessionCipher sessioncipher = new SessionCipher(sessionkey);
		HandshakeMessage handshake_message_3 = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
		
		HandshakeCrypto public_server_cryptoknight = new HandshakeCrypto(received_certificate);
		byte[] encrypted_sessionkey = public_server_cryptoknight.encrypt(sessionkey.getKeyBytes());
		byte[] encrypted_IV = public_server_cryptoknight.encrypt(sessioncipher.getIVBytes());
		
		handshake_message_3.putParameter("SessionKey", Base64.getEncoder().encodeToString(encrypted_sessionkey));
		handshake_message_3.putParameter("SessionIV", Base64.getEncoder().encodeToString(encrypted_IV));
		
		//wait for 0.2 second before sending this message
		try{
			Thread.sleep(200);
		}
		catch(Exception e){e.printStackTrace();}
		
		try{
			handshake_message_3.send(socket);
		}
		catch(Exception e){e.printStackTrace();}
		
		/*	3rd step, create the AES sessionkey and the sessioncipher (IV to be sent),
			then encrypt them with the Server's public key
			and send them to the server
		*/
		
		//4th step, send our own Signature (hash of all messages sent) and Timestamp, then wait for the server's//
		byte[] keybytes = null;
		//first we read our private key from the file that was provided//
		try{
			instream = new FileInputStream(key_path);
		}
		catch(Exception e){e.printStackTrace();}
		
		try{
			keybytes = instream.readAllBytes();
		}
		catch(Exception e){e.printStackTrace();}
		//first we read our private key from the file that was provided//
		
		//create the private_client_cryptoknight, will be used later to encrypt the hash and the TimeStamp
		HandshakeCrypto private_client_cryptoknight = new HandshakeCrypto(keybytes);
		
		//only digest messages 1 and 3 (ClientHello and Session message)
		HandshakeDigest handshake_digest = new HandshakeDigest();
		try{
			handshake_digest.update(handshake_message_1.getBytes());
			handshake_digest.update(handshake_message_3.getBytes());
		}
		catch(Exception e){e.printStackTrace();}
		byte[] final_digest = handshake_digest.digest();
		
		//get current TimeStamp
		Instant now = Instant.now();
		DateTimeFormatter TimeStamp = DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss");
		LocalDateTime localDateTime = LocalDateTime.ofInstant(now, ZoneId.systemDefault());
		ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(TimeStamp.format(localDateTime));
		
		byte[] encrypted_final_digest = private_client_cryptoknight.encrypt(final_digest);
		byte[] encrypted_TimeStamp = private_client_cryptoknight.encrypt(byteBuffer.array());
		
		HandshakeMessage handshake_message_4 = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
		
		handshake_message_4.putParameter("Signature", Base64.getEncoder().encodeToString(encrypted_final_digest));
		handshake_message_4.putParameter("TimeStamp", Base64.getEncoder().encodeToString(encrypted_TimeStamp));
		
		try{
			Thread.sleep(200);
		}
		catch(Exception e){e.printStackTrace();}
		
		try{
			handshake_message_4.send(socket);
		}
		catch(Exception e){e.printStackTrace();}
		
		//done sending, now waiting and then checking//
		
		HandshakeMessage handshake_message_5 = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
		try{
			handshake_message_5 = handshake_message_5.recv(socket);
		}
		catch(Exception e){e.printStackTrace();}
		
		String received_signature_string = null;
		String received_timestamp_string = null;
		try{
			received_signature_string = handshake_message_5.getParameter("Signature");
			received_signature_string = handshake_message_5.getParameter("TimeStamp");
		}
		catch(Exception e){e.printStackTrace();}
		
		byte[] encrypted_received_sigbytes = received_signature_string.getBytes();
		byte[] encrypted_received_timebytes = received_signature_string.getBytes();
		//now decrypt the received data, using the server's public key
		byte[] received_sigbytes = public_server_cryptoknight.decrypt(encrypted_received_sigbytes);
		byte[] received_timebytes = public_server_cryptoknight.decrypt(encrypted_received_timebytes);
		
		//create a hash of the message received from the server and compare it with the hash received now
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
		
		//done sending, done waiting and checking//
		
		//4th step, send our own Signature (hash of all messages sent) and Timestamp, then wait for the server's// 
		
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
