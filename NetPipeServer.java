import java.net.*;
import java.io.*;
//be careful with this import, it might be needed in other places too...
import java.util.Base64;

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
		
		HandshakeMessage handshake_message = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
		try{
			handshake_message = handshake_message.recv(socket);
		}
		catch(Exception e){e.printStackTrace();}
		
		//1st step, receive the client certificate in String, convert it to HandshakeCertificate and verify it//
		String received_certificate_string = null;
		try{
			received_certificate_string = handshake_message.getParameter("Certificate");
		}
		catch(Exception e){e.printStackTrace();}
		
		byte[] received_certbytes = received_certificate_string.getBytes();
		
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
		handshake_message = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
		handshake_message.putParameter("Certificate", Base64.getEncoder().encodeToString(certBytes1));
		try{
			handshake_message.send(socket);
		}
		catch(Exception e){e.printStackTrace();}
		
		//2nd step, send the server certificate to the client//
		
		/*	3rd step, receive the encrypted session_key and IV,
			decrypt them using our private key and create the necessary objects
		*/
		
		handshake_message = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
		byte[] keybytes = null;
		//first we read our private key from the file that was provided//
		/* Read the key from file */
		try{
			instream = new FileInputStream(cacert_path);
		}
		catch(Exception e){e.printStackTrace();}
		
		try{
			keybytes = instream.readAllBytes();
		}
		catch(Exception e){e.printStackTrace();}
		//first we read our private key from the file that was provided//
		//create a de-crypter
        HandshakeCrypto de_cryptoknight = new HandshakeCrypto(keybytes);
		//read the received data//
		String encrypted_session_key_string = null;
		String encrypted_IV_string = null;
		try{
			encrypted_session_key_string = handshake_message.getParameter("SessionKey");
			encrypted_IV_string = handshake_message.getParameter("SessionIV");
		}
		catch(Exception e){e.printStackTrace();}
		
		byte[] encrypted_session_key = encrypted_session_key_string.getBytes();
		byte[] encrypted_session_IV = encrypted_IV_string.getBytes();
		//read the received data//
		
		//use the de-crypter to decrypt the session_key and the IV
		byte[] session_key_bytes = de_cryptoknight.decrypt(encrypted_session_key);
		byte[] session_IV_bytes = de_cryptoknight.decrypt(encrypted_session_IV);
		
		//create the SessionKey and SessionCipher objects//
		SessionKey sessionkey = new SessionKey(session_key_bytes);
		SessionCipher sessioncipher = new SessionCipher(sessionkey, session_IV_bytes);
		//create the SessionKey and SessionCipher objects//
		
		/*	3rd step, receive the encrypted session_key and IV,
			decrypt them using our private key and create the necessary objects
		*/
		
		//execute_handshake//
		
		//forward traffic after the encryption//
		try {
            Forwarder.forwardStreams(System.in, System.out, socket.getInputStream(), socket.getOutputStream(), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
		//forward traffic after the encryption//
    }
}
