package org.coursera.aes;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

public class AESUtils {

    private static final int BLOCK_SIZE = 16;
    private static final byte[][] S_BOX = {
            {(byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76},
            {(byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0},
            {(byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc, (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15},
            {(byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75},
            {(byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0, (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84},
            {(byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b, (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf},
            {(byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8},
            {(byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2},
            {(byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73},
            {(byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb},
            {(byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79},
            {(byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9, (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08},
            {(byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a},
            {(byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e},
            {(byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf},
            {(byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16}
    };

    private static final byte[][] S_BOX_INV = {
            {(byte) 0x52, (byte) 0x09, (byte) 0x6a, (byte) 0xd5, (byte) 0x30, (byte) 0x36, (byte) 0xa5, (byte) 0x38, (byte) 0xbf, (byte) 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb},
            {(byte) 0x7c, (byte) 0xe3, (byte) 0x39, (byte) 0x82, (byte) 0x9b, (byte) 0x2f, (byte) 0xff, (byte) 0x87, (byte) 0x34, (byte) 0x8e, (byte) 0x43, (byte) 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb},
            {(byte) 0x54, (byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6, (byte) 0xc2, (byte) 0x23, (byte) 0x3d, (byte) 0xee, (byte) 0x4c, (byte) 0x95, (byte) 0x0b, (byte) 0x42, (byte) 0xfa, (byte) 0xc3, (byte) 0x4e},
            {(byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66, (byte) 0x28, (byte) 0xd9, (byte) 0x24, (byte) 0xb2, (byte) 0x76, (byte) 0x5b, (byte) 0xa2, (byte) 0x49, (byte) 0x6d, (byte) 0x8b, (byte) 0xd1, (byte) 0x25},
            {(byte) 0x72, (byte) 0xf8, (byte) 0xf6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xd4, (byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d, (byte) 0x65, (byte) 0xb6, (byte) 0x92},
            {(byte) 0x6c, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda, (byte) 0x5e, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84},
            {(byte) 0x90, (byte) 0xd8, (byte) 0xab, (byte) 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, (byte) 0x0a, (byte) 0xf7, (byte) 0xe4, (byte) 0x58, (byte) 0x05, (byte) 0xb8, (byte) 0xb3, (byte) 0x45, (byte) 0x06},
            {(byte) 0xd0, (byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca, (byte) 0x3f, (byte) 0x0f, (byte) 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8a, (byte) 0x6b},
            {(byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4f, (byte) 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, (byte) 0x73},
            {(byte) 0x96, (byte) 0xac, (byte) 0x74, (byte) 0x22, (byte) 0xe7, (byte) 0xad, (byte) 0x35, (byte) 0x85, (byte) 0xe2, (byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c, (byte) 0x75, (byte) 0xdf, (byte) 0x6e},
            {(byte) 0x47, (byte) 0xf1, (byte) 0x1a, (byte) 0x71, (byte) 0x1d, (byte) 0x29, (byte) 0xc5, (byte) 0x89, (byte) 0x6f, (byte) 0xb7, (byte) 0x62, (byte) 0x0e, (byte) 0xaa, (byte) 0x18, (byte) 0xbe, (byte) 0x1b},
            {(byte) 0xfc, (byte) 0x56, (byte) 0x3e, (byte) 0x4b, (byte) 0xc6, (byte) 0xd2, (byte) 0x79, (byte) 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, (byte) 0x78, (byte) 0xcd, (byte) 0x5a, (byte) 0xf4},
            {(byte) 0x1f, (byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xc7, (byte) 0x31, (byte) 0xb1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xec, (byte) 0x5f},
            {(byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9, (byte) 0x19, (byte) 0xb5, (byte) 0x4a, (byte) 0x0d, (byte) 0x2d, (byte) 0xe5, (byte) 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef},
            {(byte) 0xa0, (byte) 0xe0, (byte) 0x3b, (byte) 0x4d, (byte) 0xae, (byte) 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61},
            {(byte) 0x17, (byte) 0x2b, (byte) 0x04, (byte) 0x7e, (byte) 0xba, (byte) 0x77, (byte) 0xd6, (byte) 0x26, (byte) 0xe1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0c, (byte) 0x7d}
    };

    private static final byte[] RC = new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80, (byte) 0x1b, (byte) 0x36};

    public static byte[] encryptCBC(byte[] key, byte[] plaintext, byte[] iv) {
        if (Objects.isNull(iv)) {
            iv = new byte[BLOCK_SIZE];
            new SecureRandom().nextBytes(iv);
        }

        byte[] paddedPlainText = pad(plaintext);
        byte[] cypherText = new byte[iv.length + paddedPlainText.length];
        System.arraycopy(iv, 0, cypherText, 0, iv.length);

        byte[][] ivBlock = fromArrToBlock(iv);
        for (int i = 0; i < paddedPlainText.length / BLOCK_SIZE; i++) {
            byte[][] m = fromArrToBlock(Arrays.copyOfRange(paddedPlainText, i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE));
            byte[][] aesInput = xorBlock(ivBlock, m);
            byte[][] cypherTextBlock = runAES128(key, aesInput);
            System.arraycopy(fromBlockToArr(cypherTextBlock), 0, cypherText, (i + 1) * BLOCK_SIZE, BLOCK_SIZE);
            ivBlock = cypherTextBlock;
        }

        return cypherText;
    }

    public static byte[] decryptCBC(byte[] key, byte[] cypherText) {
        byte[] iv = Arrays.copyOfRange(cypherText, 0, BLOCK_SIZE);
        byte[] message = new byte[cypherText.length - iv.length];
        byte[] cypherTextWithoutIv = Arrays.copyOfRange(cypherText, BLOCK_SIZE, cypherText.length);
        byte[][] ivBlock = fromArrToBlock(iv);
        for (int i = 0; i < cypherTextWithoutIv.length / BLOCK_SIZE; i++) {
            byte[][] cypherTextBlock = fromArrToBlock(Arrays.copyOfRange(cypherTextWithoutIv, i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE));
            byte[][] decryptedBlock = runInvAES128(key, cypherTextBlock);
            byte[][] m = xorBlock(ivBlock, decryptedBlock);
            ivBlock = cypherTextBlock;
            System.arraycopy(fromBlockToArr(m), 0, message, i * BLOCK_SIZE, BLOCK_SIZE);
        }

        byte pad = message[message.length - 1];
        return Arrays.copyOfRange(message, 0, message.length - pad);
    }

    public static byte[] encryptCTR(byte[] key, byte[] plainText, byte[] iv) {
        if (Objects.isNull(iv)) {
            iv = new byte[BLOCK_SIZE];
            new SecureRandom().nextBytes(iv);
        }

        byte[] cypherText = new byte[iv.length + plainText.length];
        System.arraycopy(iv, 0, cypherText, 0, iv.length);

        byte[][] ivBlock = fromArrToBlock(iv);
        int numOfBlocks = plainText.length / BLOCK_SIZE;
        if (plainText.length % BLOCK_SIZE != 0) {
            numOfBlocks++;
        }

        for (int i = 0; i < numOfBlocks; i++) {
            byte[][] encryptedIv = runAES128(key, ivBlock);
            if (i < numOfBlocks - 1) {
                byte[][] m = fromArrToBlock(Arrays.copyOfRange(plainText, i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE));
                byte[][] cypherTextBlock = xorBlock(m, encryptedIv);
                incrementIv(ivBlock, 3, 3);
                System.arraycopy(fromBlockToArr(cypherTextBlock), 0, cypherText, (i + 1) * BLOCK_SIZE, BLOCK_SIZE);
            } else {
                byte[] m = Arrays.copyOfRange(plainText, i * BLOCK_SIZE, i * BLOCK_SIZE + (plainText.length % BLOCK_SIZE));
                byte[] encryptedIvArr = fromBlockToArr(encryptedIv);
                for (int j = 0; j < m.length; j++) {
                    cypherText[(i + 1) * BLOCK_SIZE + j] = (byte) (m[j] ^ encryptedIvArr[j]);
                }
            }
        }

        return cypherText;
    }

    public static byte[] decryptCTR(byte[] key, byte[] cypherText) {
        byte[] iv = Arrays.copyOfRange(cypherText, 0, BLOCK_SIZE);
        byte[] message = new byte[cypherText.length - iv.length];
        byte[] cypherTextWithoutIv = Arrays.copyOfRange(cypherText, BLOCK_SIZE, cypherText.length);
        byte[][] ivBlock = fromArrToBlock(iv);

        int numOfBlocks = cypherTextWithoutIv.length / BLOCK_SIZE;
        if (cypherTextWithoutIv.length % BLOCK_SIZE != 0) {
            numOfBlocks++;
        }

        for (int i = 0; i < numOfBlocks; i++) {
            byte[][] encryptedIv = runAES128(key, ivBlock);
            if (i < numOfBlocks - 1) {
                byte[][] c = fromArrToBlock(Arrays.copyOfRange(cypherTextWithoutIv, i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE));
                byte[][] cypherTextBlock = xorBlock(c, encryptedIv);
                incrementIv(ivBlock, 3, 3);
                System.arraycopy(fromBlockToArr(cypherTextBlock), 0, message, i * BLOCK_SIZE, BLOCK_SIZE);
            } else {
                byte[] c = Arrays.copyOfRange(cypherTextWithoutIv, i * BLOCK_SIZE, i * BLOCK_SIZE + (cypherTextWithoutIv.length % BLOCK_SIZE));
                byte[] encryptedIvArr = fromBlockToArr(encryptedIv);
                for (int j = 0; j < c.length; j++) {
                    message[i * BLOCK_SIZE + j] = (byte) (c[j] ^ encryptedIvArr[j]);
                }
            }
        }

        return message;
    }

    private static void incrementIv(byte[][] ivBlock, int row, int col) {
        if (ivBlock[row][col] == (byte) 0xff) {
            ivBlock[row][col] = 0x00;
            if (!(row == 0 && col == 0)) {
                if (row == 0) {
                    row = 3;
                    col--;
                } else {
                    row--;
                }
                incrementIv(ivBlock, row, col);
            } else {
                throw new RuntimeException("too many blocks encrypted with one key");
            }
        } else {
            ivBlock[row][col]++;
        }
    }

    private static byte[][] expandAES128Key(byte[] key) {
        byte[][] initKeyBlock = fromArrToBlock(key);
        byte[][] roundKeys = new byte[4][44];

        // copy key as first round key
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                roundKeys[row][col] = initKeyBlock[row][col];
            }
        }

        for (int col = 4; col < 44; col++) {
            byte[] word = new byte[4];
            if (col % 4 == 0) {
                // copy last column of previous round key
                copyColumn(word, roundKeys, col - 1);

                // rotate word
                shiftRowLeft(1, word);

                // sub word
                word[0] = lookup(word[0], S_BOX);
                word[1] = lookup(word[1], S_BOX);
                word[2] = lookup(word[2], S_BOX);
                word[3] = lookup(word[3], S_BOX);

                // XOR to round constant
                word[0] = (byte) (word[0] ^ RC[(col / 4) - 1]);

                // XOR to first column of previous round key
                word[0] = (byte) (word[0] ^ roundKeys[0][col - 4]);
                word[1] = (byte) (word[1] ^ roundKeys[1][col - 4]);
                word[2] = (byte) (word[2] ^ roundKeys[2][col - 4]);
                word[3] = (byte) (word[3] ^ roundKeys[3][col - 4]);
            } else {
                word[0] = (byte) (roundKeys[0][col - 4] ^ roundKeys[0][col - 1]);
                word[1] = (byte) (roundKeys[1][col - 4] ^ roundKeys[1][col - 1]);
                word[2] = (byte) (roundKeys[2][col - 4] ^ roundKeys[2][col - 1]);
                word[3] = (byte) (roundKeys[3][col - 4] ^ roundKeys[3][col - 1]);
            }

            roundKeys[0][col] = word[0];
            roundKeys[1][col] = word[1];
            roundKeys[2][col] = word[2];
            roundKeys[3][col] = word[3];
        }


        return roundKeys;
    }

    private static byte[][] runAES128(byte[] key, byte[][] input) {
        byte[][] roundKeys = expandAES128Key(key);
        byte[][] roundInput = xorBlock(input, copyOfSubBlock(roundKeys, 0));
        for (int r = 1; r <= 10; r++) {
            byteSub(roundInput, S_BOX);
            shiftRowsLeft(roundInput);
            if (r != 10) {
                mixColumns(roundInput);
            }
            roundInput = xorBlock(roundInput, copyOfSubBlock(roundKeys, r * 4));
        }
        return roundInput;
    }

    private static byte[][] runInvAES128(byte[] key, byte[][] input) {
        byte[][] roundKeys = expandAES128Key(key);
        byte[][] roundInput = xorBlock(input, copyOfSubBlock(roundKeys, 40));
        for (int r = 9; r >= 0; r--) {
            if (r != 9) {
                mixColumnsInv(roundInput);
            }
            shiftRowsRight(roundInput);
            byteSub(roundInput, S_BOX_INV);
            roundInput = xorBlock(roundInput, copyOfSubBlock(roundKeys, r * 4));
        }
        return roundInput;
    }

    private static void byteSub(byte[][] input, byte[][] sBox) {
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                input[row][col] = lookup(input[row][col], sBox);
            }
        }
    }

    public static byte lookup(byte b, byte[][] arr) {
        return arr[(b >> 4) & 0xf][b & 0xf];
    }

    public static void shiftRowsLeft(byte[][] arr) {
        for (int row = 1; row < 4; row++) {
            shiftRowLeft(row, arr[row]);
        }
    }

    public static void shiftRowLeft(int shift, byte[] arr) {
        for (int s = 0; s < shift; s++) {
            byte head = arr[0];
            System.arraycopy(arr, 1, arr, 0, arr.length - 1);
            arr[arr.length - 1] = head;
        }
    }

    public static void shiftRowsRight(byte[][] arr) {
        for (int row = 1; row < 4; row++) {
            shiftRowRight(row, arr[row]);
        }
    }

    public static void shiftRowRight(int shift, byte[] arr) {
        for (int s = 0; s < shift; s++) {
            byte tail = arr[arr.length - 1];
            System.arraycopy(arr, 0, arr, 1, arr.length - 1);
            arr[0] = tail;
        }
    }

    public static void mixColumns(byte[][] arr) {
        byte[] mixColumn = new byte[4];
        byte b02 = (byte) 0x02, b03 = (byte) 0x03;
        for (int col = 0; col < 4; col++) {
            mixColumn[0] = (byte) (mul(b02, arr[0][col]) ^ mul(b03, arr[1][col]) ^ arr[2][col] ^ arr[3][col]);
            mixColumn[1] = (byte) (arr[0][col] ^ mul(b02, arr[1][col]) ^ mul(b03, arr[2][col]) ^ arr[3][col]);
            mixColumn[2] = (byte) (arr[0][col] ^ arr[1][col] ^ mul(b02, arr[2][col]) ^ mul(b03, arr[3][col]));
            mixColumn[3] = (byte) (mul(b03, arr[0][col]) ^ arr[1][col] ^ arr[2][col] ^ mul(b02, arr[3][col]));

            for (int row = 0; row < 4; row++) {
                arr[row][col] = mixColumn[row];
            }
        }
    }

    public static void mixColumnsInv(byte[][] arr) {
        byte[] mixColumn = new byte[4];
        byte b09 = (byte) 0x09, b11 = (byte) 0x0b, b13 = (byte) 0x0d, b14 = (byte) 0x0e;
        for (int col = 0; col < 4; col++) {
            mixColumn[0] = (byte) (mul(b14, arr[0][col]) ^ mul(b11, arr[1][col]) ^ mul(b13, arr[2][col]) ^ mul(b09, arr[3][col]));
            mixColumn[1] = (byte) (mul(b09, arr[0][col]) ^ mul(b14, arr[1][col]) ^ mul(b11, arr[2][col]) ^ mul(b13, arr[3][col]));
            mixColumn[2] = (byte) (mul(b13, arr[0][col]) ^ mul(b09, arr[1][col]) ^ mul(b14, arr[2][col]) ^ mul(b11, arr[3][col]));
            mixColumn[3] = (byte) (mul(b11, arr[0][col]) ^ mul(b13, arr[1][col]) ^ mul(b09, arr[2][col]) ^ mul(b14, arr[3][col]));

            for (int row = 0; row < 4; row++) {
                arr[row][col] = mixColumn[row];
            }
        }
    }

    private static byte mul(byte a, byte b) {
        byte aa = a, bb = b, r = 0, t;
        while (aa != 0) {
            if ((aa & 1) != 0)
                r = (byte) (r ^ bb);
            t = (byte) (bb & 0x80);
            bb = (byte) (bb << 1);
            if (t != 0)
                bb = (byte) (bb ^ 0x1b);
            aa = (byte) ((aa & 0xff) >> 1);
        }
        return r;
    }

    private static byte[][] xorBlock(byte[][] left, byte[][] right) {
        byte[][] product = new byte[4][4];
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                product[row][col] = (byte) (left[row][col] ^ right[row][col]);
            }
        }
        return product;
    }

    private static void copyColumn(byte[] word, byte[][] roundKeys, int col) {
        for (int row = 0; row < word.length; row++) {
            word[row] = roundKeys[row][col];
        }
    }

    private static byte[][] fromArrToBlock(byte[] arr) {
        byte[][] block = new byte[4][4];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                block[row][col] = arr[col * 4 + row];
            }
        }
        return block;
    }

    private static byte[] fromBlockToArr(byte[][] block) {
        byte[] arr = new byte[16];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                arr[col * 4 + row] = block[row][col];
            }
        }
        return arr;
    }

    private static byte[][] copyOfSubBlock(byte[][] source, int from) {
        byte[][] target = new byte[4][4];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                target[row][col] = source[row][from + col];
            }
        }
        return target;
    }

    private static byte[] pad(byte[] arr) {
        int nBlocks = arr.length / 16;
        int rem = arr.length % 16;
        int newLength = (nBlocks + 1) * 16;
        byte[] res = new byte[newLength];
        System.arraycopy(arr, 0, res, 0, arr.length);
        byte pad = (byte) (0x10 - Integer.valueOf(rem).byteValue());

        for (int i = arr.length; i < newLength; i++) {
            res[i] = pad;
        }
        return res;
    }
}
