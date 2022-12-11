import java.net.*;
import java.io.*;
//be careful with this import, it might be needed in other places too...
import java.util.Base64;

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
		HandshakeMessage handshake_message = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
		handshake_message.putParameter("Certificate", Base64.getEncoder().encodeToString(certBytes1));
		try{
			handshake_message.send(socket);
		}
		catch(Exception e){e.printStackTrace();}
		//1st step, send the ClientHello message (send client certificate to server//
		
		//2nd step, wait for response from the server and validate the server certificate//
		
		handshake_message = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
		try{
			handshake_message = handshake_message.recv(socket);
		}
		catch(Exception e){e.printStackTrace();}
		
		String received_certificate_string = null;
		try{
			received_certificate_string = handshake_message.getParameter("Certificate");
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
		handshake_message = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
		
		HandshakeCrypto cryptoknight = new HandshakeCrypto(received_certificate);
		byte[] encrypted_sessionkey = cryptoknight.encrypt(sessionkey.getKeyBytes());
		byte[] encrypted_IV = cryptoknight.encrypt(sessioncipher.getIVBytes());
		
		handshake_message.putParameter("SessionKey", Base64.getEncoder().encodeToString(encrypted_sessionkey));
		handshake_message.putParameter("SessionIV", Base64.getEncoder().encodeToString(encrypted_IV));
		
		try{
			handshake_message.send(socket);
		}
		catch(Exception e){e.printStackTrace();}
		
		/*	3rd step, create the AES sessionkey and the sessioncipher (IV to be sent),
			then encrypt them with the Server's public key
			and send them to the server
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
