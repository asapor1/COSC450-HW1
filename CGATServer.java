import java.io.*;
import java.net.*;
import java.security.spec.X509EncodedKeySpec;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class CGATServer {

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int AES_KEY_BIT = 256;

    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    // AES-GCM needs GCMParameterSpec
    public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

        Cipher cip = Cipher.getInstance(ENCRYPT_ALGO);
        cip.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] encryptedText = cip.doFinal(pText);
        return encryptedText;

    }

    // prefix IV length + IV bytes to cipher text
    public static byte[] encryptWithPrefixIV(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

        byte[] cipTxt = encrypt(pText, secret, iv);

        byte[] cipherTextWithIv = ByteBuffer.allocate(iv.length + cipTxt.length)
                .put(iv)
                .put(cipTxt)
                .array();
        return cipherTextWithIv;

    }

    public static String decrypt(byte[] cText, SecretKey secret, byte[] iv) throws Exception {

        Cipher cip = Cipher.getInstance(ENCRYPT_ALGO);
        cip.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cip.doFinal(cText);
        return new String(plainText, UTF_8);

    }

    public static String decryptWithPrefixIV(byte[] cText, SecretKey secret) throws Exception {

        ByteBuffer bb = ByteBuffer.wrap(cText);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);
        //bb.get(iv, 0, iv.length);

        byte[] cipTxt = new byte[bb.remaining()];
        bb.get(cipTxt);

        String plainText = decrypt(cipTxt, secret, iv);

        return plainText;

    }
    public static void main(String[] args) {
        try {

            // Generate ephemeral ECDH keypair
            KeyPairGenerator KPG = KeyPairGenerator.getInstance("EC");
            KPG.initialize(256);
            KeyPair kP = KPG.generateKeyPair();
            byte[] ourPk = kP.getPublic().getEncoded();

            // Create a server socket and bind it to a specific port
            ServerSocket ServerSocket = new ServerSocket(24501);
            System.out.println("Listening to Port 24501...");
            System.out.println("Server is waiting for a client to connect...");

            // Accept a client connection
            Socket ClientSocket = ServerSocket.accept();
            System.out.println("Client connected: " + ClientSocket.getInetAddress());

            // Create input and output streams for communication with the client
            InputStream inStream = ClientSocket.getInputStream();
            OutputStream outStream = ClientSocket.getOutputStream();

            // Read the byte array sent by the client
            int pKeyLen = inStream.read();
            byte[] clientPublicKey = new byte[pKeyLen];
            int bytesRead = inStream.read(clientPublicKey);

            System.out.println("Recieved Public Key From Client");
            System.out.println("Sharing Public Key...");
            // Send the byte array to the server
            outStream.write(ourPk.length);
            outStream.write(ourPk);


            System.out.println("Generating Derived Secret Key...");

            //Perform KeyFactory
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(clientPublicKey);
            PublicKey otherPublicKey = kf.generatePublic(pkSpec);


            // Perform key agreement
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kP.getPrivate());
            ka.doPhase(otherPublicKey, true);

            // Read shared secret
            byte[] sharedSecret = ka.generateSecret();

            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(sharedSecret);

            List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(clientPublicKey));
            Collections.sort(keys);
            hash.update(keys.get(0));
            hash.update(keys.get(1));


            //Get the derived key
            byte[] derivedKey = hash.digest();
            System.out.println("Generated derived key");
            System.out.println("Password: "+Arrays.toString(derivedKey));



            // Read the Encrypted Message sent by the client
            int eMsgLen = inStream.read();
            byte[] eMsg = new byte[eMsgLen];
            bytesRead = inStream.read(eMsg);

            System.out.println("Recieved Encrypted Message From Client. Decrypting...");

            //Convert byte[] to secret key
            SecretKey secretKey = new SecretKeySpec(derivedKey, 0, derivedKey.length, "AES");
        
            //Decrept Message
            String decryptedText = CGATServer.decryptWithPrefixIV(eMsg, secretKey);
            System.out.println(String.format("Decrypted (plain text): "+ decryptedText));

            System.out.println("Successfully Finished Running. Closing Socket...");
            // Close the connections
            ClientSocket.close();
            ServerSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
