package org.example;

import jdk.nashorn.internal.runtime.ECMAException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;


public class myAES {

    private SecretKey key;
    private final int KEY_SIZE = 128;
    private final int DATA_LENGTH = 128;
    private Cipher encryptCipher;

    public myAES( ){}

    public void init() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(KEY_SIZE);
        this.key = keyGen.generateKey();
    }

    public byte[] encrypt (String data) throws Exception{
        init();
       // System.out.println("Printing out key here:"+this.key);
        byte[] dataInBytes = data.getBytes();
        encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptCipher.doFinal(dataInBytes);
        return encryptedBytes;
    }

    public String decrypt (byte[] encryptedData, Key aes_key) throws Exception
    {

        Cipher dCipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        dCipher.init(Cipher.DECRYPT_MODE, aes_key);
        byte[] dBytes = dCipher.doFinal(encryptedData);
        return new String(dBytes, StandardCharsets.UTF_8);
    }

    public byte[] getAESKeyBytes()
    {
        byte [] key_bytes = this.key.getEncoded();
        return key_bytes;
    }

}
