package org.example;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class MAC {

    /***
     *

     * @return byte
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     *  Static method to Create MAC and
     */
    public static byte[] CreateMac(byte[] encryptedMessage,byte[] encryptedAESkey, Key sharedKey) throws NoSuchAlgorithmException, InvalidKeyException {

        //creating the MAC object
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(sharedKey);
        mac.update(encryptedMessage);
        mac.update(encryptedAESkey);
        //print the final mac generated to see the contents and use for comparison
        byte[] mac_bytes = mac.doFinal();
        System.out.println("Printing mac from MAC class: "+  Base64.getEncoder().encodeToString(mac_bytes));
        return mac_bytes;
    }
    /***
    public static boolean verifyMac (byte[] message, Key sharedKey)
    {
        boolean isValid = true;

    }***/

}
