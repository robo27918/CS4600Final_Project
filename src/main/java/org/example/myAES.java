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
        System.out.println("Printing out key here:"+this.key);
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
    private String encode (byte[] data)
    {
        return Base64.getEncoder().encodeToString(data);
    }
    private byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }
    public byte[] getAESKeyBytes()
    {
        byte [] key_bytes = this.key.getEncoded();
        return key_bytes;
    }
    public SecretKey getAESKey () {return this.key;}
    /***
    public static void setKey(final String myKey) {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }***/
    /***
    public static String encrypt(String strToEncrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); //might have to change this for our system later!!!
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt( String strToDecrypt,String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder()
                    .decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }***/
}
