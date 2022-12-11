package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSA
{


    public RSA() throws NoSuchPaddingException, NoSuchAlgorithmException {
    }

    public static byte[] encryptAESKey(String pathToPubKey, byte[] AES_key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //get the public key needed


        byte [] publicKey_bytes = Utils.readToBytes(pathToPubKey);
        System.out.println("Checking Bob's public key from RSA class!: "
                + Base64.getEncoder().encodeToString(publicKey_bytes));

        System.out.println("should have printed bob's key!!!");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey_bytes);

        // creating object of keyfactory
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // generating Public key from the provided key spec.
        // using generatePublic() method
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);



        Cipher cip = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cip.init(Cipher.ENCRYPT_MODE, publicKey);
        return cip.doFinal(AES_key);



    }
    public static byte [] decryptAESkey (String pathToPrivKey, byte[] encAES_key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte [] publicKey_bytes = Utils.readToBytes(pathToPrivKey);

        KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(publicKey_bytes);
        PrivateKey privateKey = privateKeyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init (Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encAES_key);

    }
}
