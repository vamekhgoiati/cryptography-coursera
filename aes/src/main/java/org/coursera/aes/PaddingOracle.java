package org.coursera.aes;

import org.apache.commons.codec.binary.Hex;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;

public class PaddingOracle {
    private static final int BLOCK_SIZE = 16;
    private static final String TARGET_URL = "http://crypto-class.appspot.com/po?er=";
    private static final String C = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4";

    public static byte[] decrypt(String cypherText) throws Exception {
        byte[] cypherTextBytes = Hex.decodeHex(cypherText);
        byte[] cypherWithoutIv = Arrays.copyOfRange(cypherTextBytes, BLOCK_SIZE, cypherTextBytes.length);
        byte[] plainText = new byte[cypherTextBytes.length - BLOCK_SIZE];
        byte[] intermediateGuesses = new byte[cypherTextBytes.length - BLOCK_SIZE];
        final int numOfBlocks = cypherTextBytes.length / BLOCK_SIZE;

        Thread[] threads = new Thread[numOfBlocks - 1];
        for (int i = 0; i < numOfBlocks - 1; i++) {
            byte[] attackBlock = Arrays.copyOfRange(cypherTextBytes, i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
            byte[] targetBlock = Arrays.copyOfRange(cypherTextBytes, (i + 1) * BLOCK_SIZE, (i + 2) * BLOCK_SIZE);
            final int blockN = i;
            threads[i] = new Thread(() -> checkOneBlock(attackBlock, targetBlock, intermediateGuesses, blockN));
            threads[i].start();
        }

        for (Thread t : threads) {
            t.join();
        }

        for (int i = 0; i < intermediateGuesses.length; i++) {
            plainText[i] = (byte) (intermediateGuesses[i] ^ cypherTextBytes[i]);
        }

        System.out.println(new String(plainText));

        return plainText;
    }

    private static void checkOneBlock(byte[] attackBlock, byte[] targetBlock, byte[] results, int blockN) {
        try {
            byte[] result = new byte[BLOCK_SIZE];
            for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
                byte counter = 0x00;
                int pad = BLOCK_SIZE - i;
                for (int j = i + 1; j < BLOCK_SIZE; j++) {
                    attackBlock[j] = (byte) (pad ^ result[j]);
                }
                for (int c = 0; c < 256; c++) {
                    attackBlock[i] = counter;
                    counter++;
                    if (404 == checkRequest(Hex.encodeHexString(attackBlock) + Hex.encodeHexString(targetBlock))) {
                        result[i] = (byte) (attackBlock[i] ^ pad);
                        break;
                    }
                }
            }

            System.arraycopy(result, 0, results, blockN * BLOCK_SIZE, BLOCK_SIZE);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static int checkRequest(String param) throws Exception {
        URL url = new URL(TARGET_URL + param);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        int result = con.getResponseCode();
        con.disconnect();
        return result;
    }

    public static void main(String[] args) throws Exception {
        decrypt(C);
    }
}
