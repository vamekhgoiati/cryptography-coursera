package org.coursera.aes;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.security.MessageDigest;
import java.util.Arrays;

public class FileSigner {
    private static final int BLOCK_SIZE = 1024;
    private static final int HASH_SIZE = 32;

    public static byte[] sign(File file) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] fileBytes = FileUtils.readFileToByteArray(file);
        int numOfBlocks = fileBytes.length / BLOCK_SIZE;
        if (fileBytes.length % BLOCK_SIZE != 0) {
            numOfBlocks++;
        }

        byte[] curHash = new byte[HASH_SIZE];
        for (int i = numOfBlocks - 1; i >= 0; i--) {
            if (i == (numOfBlocks - 1)) {
                byte[] block = Arrays.copyOfRange(fileBytes, i * BLOCK_SIZE, i * BLOCK_SIZE + fileBytes.length % BLOCK_SIZE);
                curHash = sha256.digest(block);
            } else {
                byte[] block = Arrays.copyOfRange(fileBytes, i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
                byte[] blockWithHash = new byte[BLOCK_SIZE + HASH_SIZE];
                System.arraycopy(block, 0, blockWithHash, 0, BLOCK_SIZE);
                System.arraycopy(curHash, 0, blockWithHash, BLOCK_SIZE, HASH_SIZE);
                curHash = sha256.digest(blockWithHash);
            }
        }

        return curHash;
    }
}
