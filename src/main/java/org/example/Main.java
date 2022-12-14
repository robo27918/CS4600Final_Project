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

        //making an Alice and Bob instance
        Alice theSender = new Alice();
        Bob theReceiver = new Bob();

        //setting the MAC key for both users-- assume that they already safely exchanged this prior to this simulation
        theSender.setSharedMacKey(sharedMACkey);
        theReceiver.setSharedMacKey(sharedMACkey);

        //msgInfo will be used in Alice instance to tell Bob where certain contents start and end
        MessageInfo msgInfo = new MessageInfo();

        //this writes the message from messages.txt to transmittedData.txt
        theSender.encryptMessageAndSendAll("src/main/resources/messages.txt",msgInfo);


        theReceiver.receiveTransmittedData(msgInfo);
        System.out.println("verifying mac in Main with Bob verify method:"+ theReceiver.verifyMac());
        theReceiver.decryptMessage();
    }

}