package org.example;

public class MessageInfo {


    private int lengthEncrytedMessage;
    private int lenEncryptedAES;
    private int lenMAC;

    public void setLenMAC(int lenMAC) {
        this.lenMAC = lenMAC;
    }



    public void setLenEncryptedAES(int lenEncryptedAES) {
        this.lenEncryptedAES = lenEncryptedAES;
    }

    public void setLengthEncrytedMessage(int lengthEncrytedMessage) {
        this.lengthEncrytedMessage = lengthEncrytedMessage;
    }

    public int getLengthEncrytedMessage() {
        return lengthEncrytedMessage;
    }

    public int getLenEncryptedAES() {
        return lenEncryptedAES;
    }

    public int getLenMAC() {
        return lenMAC;
    }

}
