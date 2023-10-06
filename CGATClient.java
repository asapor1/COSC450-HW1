import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CGATClient {

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int AES_KEY_BIT = 256;

    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

        Cipher cip = Cipher.getInstance(ENCRYPT_ALGO);
        cip.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] encryptedText = cip.doFinal(pText);
        return encryptedText;

    }

    // prefix IV length + IV bytes to cipher text
    public static byte[] encryptWithPrefixIV(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

        byte[] cipTxt = encrypt(pText, secret, iv);

        byte[] cipTxtWithIv = ByteBuffer.allocate(iv.length + cipTxt.length)
                .put(iv)
                .put(cipTxt)
                .array();
        return cipTxtWithIv;

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
            // Create a socket and connect it to the server's IP address and port
            System.out.println("Listening on Port 24501...");
            Socket socket = new Socket("localhost", 24501);
            System.out.println("Connected to server!");
            

            // Create input and output streams for communication with the server
            InputStream inputStream = socket.getInputStream();
            OutputStream OutputStream = socket.getOutputStream();

            // Create a byte array to send to the server
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair KP = kpg.generateKeyPair();
            byte[] ourPk = KP.getPublic().getEncoded();
    
            System.out.println("Sharing public key now...");
            // Send the byte array to the server
            OutputStream.write(ourPk.length);
            OutputStream.write(ourPk);

            // Read the byte array sent by the server
            int pKeyLength = inputStream.read();
            byte[] clientPublicKey = new byte[pKeyLength];
            int bytsRead = inputStream.read(clientPublicKey);
            System.out.println("Recieved Public Key From Server.");

            System.out.println("Generating Derived Secret Key...");

            //Perform KeyFactory
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(clientPublicKey);
            PublicKey otherPublicKey = kf.generatePublic(pkSpec);


            // Perform key agreement
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(KP.getPrivate());
            ka.doPhase(otherPublicKey, true);

            // Read shared secret
            byte[] shareSecret = ka.generateSecret();

            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(shareSecret);

            List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(clientPublicKey));
            Collections.sort(keys);
            hash.update(keys.get(0));
            hash.update(keys.get(1));

            byte[] derivedKey = hash.digest();
            System.out.println("Generated derived key");
            System.out.println("Password : "+Arrays.toString(derivedKey));


            //Begin AES Message Encryption
            String message = "Hello Client!";
            System.out.println("Message To Be Sent M: '"+message+"'");
            System.out.println("Encrypting and Sending Message...");

            byte[] iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE);
            SecretKey secretKey = new SecretKeySpec(derivedKey, 0, derivedKey.length, "AES");

            byte[] encryptedText = CGATClient.encryptWithPrefixIV(message.getBytes(UTF_8), secretKey, iv);
            
            // Send the encrypted Array to the server
            OutputStream.write(encryptedText.length);
            OutputStream.write(encryptedText);

            System.out.println("Successfully Finished Running. Closing Socket...");

            // Close the connection
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
