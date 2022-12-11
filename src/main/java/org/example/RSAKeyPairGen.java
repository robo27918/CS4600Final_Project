package org.example;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.util.Base64;

/***
 * obsolete
 */
//https://www.devglan.com/java8/rsa-encryption-decryption-java
public class RSAKeyPairGen {
    private PrivateKey privateKey;
    private PublicKey pubKey;

    /***
     * Constructor to generate RSA Key pair
     * @throws NoSuchAlgorithmException
     */
    public RSAKeyPairGen () throws NoSuchAlgorithmException
    {
        //update to use SecureRandom
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.pubKey = pair.getPublic();
    }
    public void ByteToFile (String path, byte[] key) throws IOException
    {
        File f = new File (path);
        f.getParentFile().mkdirs();

        FileOutputStream fileOutput = new FileOutputStream(f);
        fileOutput.write(key);
        fileOutput.flush();
        fileOutput.close();

    }

    public void StringToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        //f.getParentFile().mkdirs();

        FileWriter fileOutput = new FileWriter(f,true);
        String keyToString = Base64.getEncoder().encodeToString(key);
        fileOutput.write(keyToString+"\n");
        fileOutput.flush();
        fileOutput.close();
    }
    public PrivateKey getPrivateKey(){ return privateKey;}
    public PublicKey getPubKey(){return pubKey;}
}
