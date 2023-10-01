import java.net.*;
import java.io.*;

public class groupnamea1client {
    public static void main(String[] args) throws IOException {
        Socket s = new Socket("localhost", 24501);
        DataOutputStream dout = new DataOutputStream(s.getOutputStream());
        
        // Generate key pairs (CPub, CPri)
        // Exchange CPub with server
        // Use ECDH to generate the shared derived key K
        // Print "generated derived key"
        
        // Convert the derived key K into the password string P
        // Print "password:" and P
        // Use P as the password for AES GCM encryption and decryption
        String M = "This is a message from the client.";
        System.out.println("message M: " + M);
        
        // Use AES GCM to encrypt M
        String encryptedM = "";  // replace with actual encryption code
        
        dout.writeUTF(encryptedM);
        dout.flush();
        dout.close();
        s.close();
    }
}
