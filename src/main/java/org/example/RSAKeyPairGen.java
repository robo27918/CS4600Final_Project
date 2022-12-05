package org.example;

import java.security.*;

//https://www.devglan.com/java8/rsa-encryption-decryption-java
public class RSAKeyPairGen {
    private PrivateKey privateKey;
    private PublicKey pubKey;

    public RSAKeyPairGen () throws NoSuchAlgorithmException
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.pubKey = pair.getPublic();
    }
}
