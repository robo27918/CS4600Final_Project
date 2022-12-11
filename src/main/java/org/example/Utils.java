package org.example;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

/***
 *
 * used to create static methods that might be used by both Alice and Bob
 */
public class Utils {
    public static String getMessagesFrom (String fileName) throws FileNotFoundException {
        String output  = "";
        File file = new File(fileName);
        Scanner input = new Scanner(file);
        while (input.hasNextLine()){
            output += input.nextLine();
        }


        return output;
    }
    public static byte[] readToBytes(String path) throws IOException {
        Path path_ = Paths.get(path);
        byte[] data = Files.readAllBytes(path_);
        return data;
    }
    public static void ByteToFile (String path, byte[] bytes) throws IOException
    {

        File f = new File (path);
        f.getParentFile().mkdirs();

        FileOutputStream fileOutput = new FileOutputStream(f);
        fileOutput.write(bytes);
        fileOutput.flush();
        fileOutput.close();

    }

    public static void writeFinalByteLoadToFile (String path, byte[]msg, byte []aes_key, byte[]MAC) throws IOException {
        File f = new File (path);
        f.getParentFile().mkdirs();

        FileOutputStream fileOutput = new FileOutputStream(f);
        fileOutput.write(msg);
        fileOutput.write(aes_key);
        fileOutput.write(MAC);
        fileOutput.flush();
        fileOutput.close();



    }
}
