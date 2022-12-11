package org.example;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.io.IOException;
import java.security.*;

/***
 * The Class Bob is used to simulate a receiving party in the secure communication system
 */
public class Bob {
    private byte[] privateKey;
    private byte[] publicKey;
    private String privateKeyFile = "src/main/resources/Bob_private_key.txt";
    private String publicKeyFile = "src/main/resources/bob_public_key.txt";
    private Key sharedMACkey;
    private byte[] msg;
    private byte[] aes_enc;
    private byte[] mac_bytes;

    public Bob () throws NoSuchAlgorithmException, IOException {
        //just make a straight call to generate public-private key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

        // initializing with 1024
        kpg.initialize(1024);

        // getting key pairs
        // using generateKeyPair() method
        KeyPair kp = kpg.genKeyPair();

        // getting public key
        PublicKey pub = kp.getPublic();
        PrivateKey prv = kp.getPrivate();

        byte[] publicKeyBytes = pub.getEncoded();
        byte[] privateKeyBytes = prv.getEncoded();
        this.privateKey = privateKeyBytes;
        this.publicKey = publicKeyBytes;
        //write the private and public key to the corresponding files
        Utils.ByteToFile(this.publicKeyFile, publicKeyBytes);
        Utils.ByteToFile(this.privateKeyFile,privateKeyBytes );

    }
    public void decryptMessage ( Key aes_Key) throws Exception {
        byte[] encryptedMessage = Utils.readToBytes("src/main/resources/transmittedData.txt");
        myAES aes = new myAES();
        String decryptedString = aes.decrypt(encryptedMessage, aes_Key);
        System.out.println("printing out of decrypted message:" + decryptedString);
    }
    public Boolean verifyMac () throws NoSuchAlgorithmException, InvalidKeyException {
        //have
        System.out.println();
        System.out.println("sharedMac key from BOB: " +
                Base64.getEncoder().encodeToString( sharedMACkey.getEncoded()));
        System.out.println("Message from Bob: " +Base64.getEncoder().encodeToString(this.msg) );
        System.out.println("AES key from Bob: " +Base64.getEncoder().encodeToString(this.aes_enc) );
        System.out.println("MAC from Bob: " +Base64.getEncoder().encodeToString(this.mac_bytes ));
        byte[] verifyMe = MAC.CreateMac(msg,aes_enc,sharedMACkey);
        return Arrays.equals(verifyMe, mac_bytes);
    }

    public byte[] decryptAESkey () throws NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        byte [] decAES = RSA.decryptAESkey(privateKeyFile,aes_enc);
        System.out.println("AES decrypted from BOB: " +Base64.getEncoder().encodeToString(decAES) );
        return decAES;
    }
    public void decryptMessage() throws Exception {
        byte[] aes_key = decryptAESkey();
        SecretKeySpec secretKeySpec = new SecretKeySpec(aes_key, "AES");
        myAES aes = new myAES();
        System.out.println("Message decrypted on Bob side:\n" + aes.decrypt(msg, secretKeySpec));
    }





    public byte[] getPrivateKey() {return this.privateKey;}
    public byte[] getPublicKey(){return this.publicKey;}
    public void setSharedMacKey (Key macKey){this.sharedMACkey = macKey;}
    public Key getSharedMacKey(){ return this.sharedMACkey; }

    public void receiveTransmitedData (byte[]msg, byte[] aes_enc, byte[] mac_bytes)
    {
        this.msg = msg;
        this.aes_enc = aes_enc;
        this.mac_bytes = mac_bytes;
    }
}
