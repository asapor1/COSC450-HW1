import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyAgreement;

public class CGATa1client {
    public static void main(String[] args) throws Exception {
        Socket clientSocket = new Socket("localhost", 24501);
        DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
        BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        // Generate ephemeral ECDH keypair (client-side)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        byte[] pkBytes = kp.getPublic().getEncoded();
        String pk = "Alice's key: ";
        int decimal;
        String hex;
        for (byte aByte : pkBytes) {
            decimal = (int) aByte + 128;
            hex = Integer.toHexString(decimal);
            if (hex.length() % 2 == 1) {
                hex = hex + "0";
            }
            pk = pk.concat(hex);
        }
        String pkey;
        pkey = inFromServer.readLine();
        System.out.printf("%s%n", pkey);
        outToServer.writeBytes(pk + '\n');
        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(pkBytes);
        PublicKey publicKey = kf.generatePublic(pkSpec);
    }
}