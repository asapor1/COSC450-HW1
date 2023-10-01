import java.net.*;
import java.io.*;

public class groupnamea1server {
    public static void main(String[] args) throws IOException {
        ServerSocket ss = new ServerSocket(24501);
        Socket s = ss.accept();
        
        DataInputStream din = new DataInputStream(s.getInputStream());
        
        // Generate key pairs (SPub, SPri)
        // Exchange SPub with client
        // Use ECDH to generate the shared derived key K
        // Print "generated derived key"
        
        // Convert the derived key K into the password string P
        // Print "password:" and P
        // Use P as the password for AES GCM encryption and decryption
        
        String encryptedM = din.readUTF();
        
        // Decrypt encryptedM using AES GCM
        String M = "";  // replace with actual decryption code
        
        System.out.println("message M: " + M);
        
        din.close();
    }
}
