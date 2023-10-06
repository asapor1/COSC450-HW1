import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.io.*;
import javax.crypto.KeyAgreement;

// "Alice" = client; "Bob" = server
public class CGATa1server {
    
    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(24501);
        while (true) {
            Socket connectionSocket = serverSocket.accept();
            BufferedReader inFromClient = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
            DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
            // Generate ephemeral ECDH keypair (server-side)
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair kp = kpg.generateKeyPair();
            // Generate byte arrays for Alice & Bob's public key
            byte[] pkBytesS = kp.getPublic().getEncoded();
            byte[] pyBytesC = new byte[pkBytesS.length];
            // Transmit Bob's public key & receive Alice's public key (1 byte at a time)
            for (int i = 0; i < pkBytesS.length; i++) {
                outToClient.writeByte(pkBytesS[i]);
            }

            // Receive Alice's public key
            String pkey;
            pkey = inFromClient.readLine();
            System.out.println(pkey);
            /*String pk = "Alice's key: ";
            int decimal;
            String hex;
            for (int i = 0; i < pkey.length(); i++) {
                decimal = (int) pkey.charAt(i) + 128;
                hex = Integer.toHexString(decimal);
                if (hex.length() % 2 == 1) {
                    hex = hex + "0";
                }
                pk = pk.concat(hex);
            }
            System.out.printf("%s%n", pk);
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(pkBytes);
            PublicKey publicKey = kf.generatePublic(pkSpec);
            // Perform key agreement
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kp.getPrivate());
            ka.doPhase(publicKey, true);
        }

        // Read shared secret
        //byte[] sharedSecret = ka.generateSecret();
        //console.printf("Shared secret: %s%n", printHexBinary(sharedSecret));

        // Derive a key from the shared secret and both public keys
        //MessageDigest hash = MessageDigest.getInstance("SHA-256");
        //hash.update(sharedSecret);
        // Simple deterministic ordering
        //List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(pkBytes), ByteBuffer.wrap(pkA));
        //Collections.sort(keys);
        //hash.update(keys.get(0));
        //hash.update(keys.get(1));

        //byte[] derivedKey = hash.digest();
        //console.printf("Final key: %s%n", printHexBinary(derivedKey));*/

        }
    }
}