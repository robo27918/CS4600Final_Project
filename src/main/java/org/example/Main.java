package org.example;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/***
 * Requirements for project
         * 1.)  The two parties have each other’s RSA public key. Each of them holds his/her own RSA
         * private key.
         * 2.)  Each party’s message (from a .txt file) is encrypted using AES before sending it to
         * another party.
         * 3.)  The AES key used in 2) is encrypted using the receiver’s RSA public key.  The encrypted
         * AES key is sent together with the encrypted message obtained from 2).
         * 4.)  Message authentication code should be appended to data transmitted. You are free to
         * choose the specific protocol of MAC.
         * 5.)  The receiver should be able to successfully authenticate, decrypt the message, and read
         * the original message.
 *
 *
 * Implementation guide:
     * You can just use local files as the channel to
     * simulate the communication in the network. For example, to implement requirement 1 above, we
     * let each party locally generate a key pair and save each key in a corresponding file. The other
     * party will be able to know the public key by accessing the file. You can create a file called
     * “Transmitted_Data”, which can include all data transmitted between sender and receiver, i.e.,
     * encrypted message, encrypted AES key, and the MAC. This file is written by the sender and read
     * by the receiver
 *
 *
 */
public class Main {
    public static void main(String[]args) throws Exception {
        //code to generate shared key for the MAC
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");

        //Creating SecureRandom Object
        SecureRandom secRandom = new SecureRandom();

        //Initializing the KeyGenerator
        keyGen.init(secRandom);

        //Creating  a random key
        Key sharedMACkey = keyGen.generateKey();

        //making an Alice and Bob instance for testing purposes
        Alice theSender = new Alice();
        Bob theReceiver = new Bob();
        //setting the MAC key for both users-- assume that they already safely exchanged this prior to this simulation
        theSender.setSharedMacKey(sharedMACkey);
        theReceiver.setSharedMacKey(sharedMACkey);
        //print the sharedMacKey for Alice
        System.out.println("sharedMac key from main method: " +
                Base64.getEncoder().encodeToString(theSender.getSharedMacKey().getEncoded()));

        System.out.println("sharedMac key from main method: " +
                Base64.getEncoder().encodeToString(theReceiver.getSharedMacKey().getEncoded()));
        System.out.println();





        byte[] alicePublicKey = theSender.getPublicKey();
        byte[] alicePrivateKey = theSender.getPrivateKey();

        byte[]bobPK = theReceiver.getPublicKey();
        byte[]bobPrivK = theReceiver.getPrivateKey();

        System.out.println("Alice public key: " + Base64.getEncoder().encodeToString(alicePrivateKey) );
        System.out.println("Alice private key: " + Base64.getEncoder().encodeToString(alicePublicKey));

        //lets check here if we can make Bob's privK
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(bobPK);
        System.out.println(pubKeySpec.getFormat());
        PublicKey pub =  kf.generatePublic(pubKeySpec);
        //System.out.println("Getting format of Bob's public key"+ pubKeyCheck.getFormat());
        System.out.println("Bob private key: " + Base64.getEncoder().encodeToString(bobPrivK));
        System.out.println("Bob public key: " + Base64.getEncoder().encodeToString(bobPK));
        //MessageInformation so bob can read the file correctly
        MessageInfo msgInfo = new MessageInfo();
        theSender.encryptMessageAndSend("src/main/resources/messages.txt",msgInfo);
        // getting the contents of the sent message somehow
        byte []transmitted_msg = Utils.readToBytes("src/main/resources/transmittedData.txt");

        //SecretKey aesKey = theSender.getAES_secret_key();
        //System.out.println("AES key printed in main:"+aesKey);
        byte[] message = new byte[msgInfo.getLengthEncrytedMessage()];
        byte[] aesEncrypted = new byte[msgInfo.getLenEncryptedAES()];
        byte[] mac = new byte[msgInfo.getLenMAC()];

        splitByteArray(message, aesEncrypted,mac,transmitted_msg);

        //get message from Alice
        System.out.println("Checking arrays in main:"+ Arrays.equals(theSender.getMsg(), message) );

        System.out.println("Message from main method: " +Base64.getEncoder().encodeToString(message) );
        System.out.println("AES key from main method: " +Base64.getEncoder().encodeToString(aesEncrypted) );
        System.out.println("MAC from main method: " +Base64.getEncoder().encodeToString(mac ));
        System.out.println("Got the contents!");

        theReceiver.receiveTransmitedData(message, aesEncrypted, mac);
        System.out.println("verifying mac in Main with Bob verify method:"+ theReceiver.verifyMac());
        theReceiver.decryptAESkey();
        theReceiver.decryptMessage();
    }
    public static void splitByteArray(byte[] message, byte[] aesEncrypted, byte[] mac ,byte[] input) {

        System.arraycopy(input, 0, message, 0, message.length);
        System.arraycopy(input, message.length, aesEncrypted, 0, aesEncrypted.length);
        System.arraycopy(input, message.length + aesEncrypted.length, mac, 0, mac.length);
        //print Mac to see if it is correct



    }
}