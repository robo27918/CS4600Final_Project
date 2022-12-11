package org.example;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.util.Base64;



/***
 * This class is used to simulate a sending party in the secure communication system to
 * be implemented
 */
public class Alice {
    /***
     *
     * Step 1: generate a private key to  be stored in Alice txt file
     *
     */
    private byte[] privateKey;
    private byte[] publicKey;
    private String privateKeyFile = "src/main/resources/Alice_private_key.txt";
    private String publicKeyFile = "src/main/resources/alice_public_key.txt";
    private String pathToBobsPK = "src/main/resources/bob_public_key.txt";
    private String  pathToTransmit = "src/main/resources/transmittedData.txt";
    private String message_alice;
    private SecretKey AES_secret_key;
    private Key sharedMACkey;


    private byte[] msg;
    private byte[] mac;
    private byte[] en_aes;





    public Alice () throws NoSuchAlgorithmException, IOException {
        //just make a straight call to generate public-private key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");

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



    public void encryptMessageAndSend(String fileName, MessageInfo msgInfo) throws Exception {
        /**
         * fileName is the placeholder for the file we should be reading messages from
         */
        // (1) get the message (s) from the file message.txt
        String message = Utils.getMessagesFrom(fileName);
        //System.out.println("Message before encrypting " + message);
        myAES aes = new myAES();
        // (2) encrypt the message read from the file
        this.msg = aes.encrypt(message);

        //refernce to key used for AES
        byte[] aes_key= aes.getAESKeyBytes();
        //need to encrypt this using Bob's public key
        System.out.println("AES key before Encryption in Alice: " +Base64.getEncoder().encodeToString(aes_key) );
        //implement this in RSA class
        this.en_aes= RSA.encryptAESKey(pathToBobsPK,aes_key);

        //generate mac for the concatenation of message and RSA key
        this.mac = MAC.CreateMac(msg,en_aes,sharedMACkey);

        //Prints for testing purposes
        System.out.println("Printing  encrypted message from Alice class: "+Base64.getEncoder().encodeToString(msg));
        System.out.println("Printing  encrypted aes_key from Alice class: "+Base64.getEncoder().encodeToString(en_aes));
        System.out.println("Printing  encrypted mac from Alice class: "+Base64.getEncoder().encodeToString(mac));
        System.out.println();

        msgInfo.setLenEncryptedAES(en_aes.length);
        msgInfo.setLengthEncrytedMessage(msg.length);
        msgInfo.setLenMAC(mac.length);
        //time to write all the different components to the transmittedData.txt
        Utils.writeFinalByteLoadToFile(pathToTransmit,msg, en_aes,mac);

        //run this line once top is implemented
        //Utils.ByteToFile( "src/main/resources/transmittedData.txt", encryptedMessage);


    }
    /***
    public void writeToFile (byte[] encryptedMessage) {
        try {
            FileWriter writer = new FileWriter("src/main/resources/transmittedData.txt");
            writer.write(String.valueOf(encryptedMessage));
            writer.close();
            System.out.println("Successfully sent encrypted message");
        }
        catch (IOException e){
            System.out.println("An error occured");
            e.printStackTrace();
        }
    }
     ***/

    //public String generateMAC(String encrypted_message) throws NoSuchAlgorithmException, InvalidKeyException {
        /***
         * Generate MAC for message authentication
         * Remember that Alice and Bob must share message Authentication
         */
      //  byte[] message_mac = MAC.CreateMac(encrypted_message);
        //String message_macString = Base64.getEncoder().encodeToString(message_mac);
       // System.out.println("MAC for encrypted message: " + message_macString);

        //return message_macString;
    //}


    public byte[] getPrivateKey() {return this.privateKey;}
    public byte[] getPublicKey(){return this.publicKey;}
    public String getPlainTxtMessage () {return message_alice;}
    public SecretKey getAES_secret_key() {return AES_secret_key;}
    public void setAES_secret_key(SecretKey AES_secret_key) {this.AES_secret_key = AES_secret_key;}
    public void setSharedMacKey (Key macKey){this.sharedMACkey = macKey;}
    public Key getSharedMacKey(){ return this.sharedMACkey; }

    public byte[] getMsg() {
        return msg;
    }

    public void setMsg(byte[] msg) {
        this.msg = msg;
    }

    public byte[] getMac() {
        return mac;
    }

    public void setMac(byte[] mac) {
        this.mac = mac;
    }

    public byte[] getEn_aes() {
        return en_aes;
    }

    public void setEn_aes(byte[] en_aes) {
        this.en_aes = en_aes;
    }




}
