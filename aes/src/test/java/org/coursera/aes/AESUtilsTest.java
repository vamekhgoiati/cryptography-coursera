package org.coursera.aes;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

class AESUtilsTest {

    @Test
    void testAesCBCEncrypt() throws Exception {
        String key = "140b41b22a29beb4061bda66b6747e14";
        byte[] keyArr = Hex.decodeHex(key);
        String cypherText = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
        byte[] cypherTextArr = Hex.decodeHex(cypherText);
        byte[] iv = Arrays.copyOfRange(cypherTextArr, 0, 16);
        String plainText = "Basic CBC mode encryption needs padding.";
        byte[] plainTextArr = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encoded = AESUtils.encryptCBC(keyArr, plainTextArr, iv);
        Assertions.assertEquals(cypherText, Hex.encodeHexString(encoded));
    }

    @Test
    void testAesCBCDecrypt() throws Exception {
        String key = "140b41b22a29beb4061bda66b6747e14";
        byte[] keyArr = Hex.decodeHex(key);
        String cypherText = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
        byte[] cypherTextArr = Hex.decodeHex(cypherText);
        String plainText = "Basic CBC mode encryption needs padding.";
        byte[] decoded = AESUtils.decryptCBC(keyArr, cypherTextArr);
        Assertions.assertEquals(plainText, new String(decoded));
    }

    @Test
    void testAesCBCEncDec() throws Exception {
        String key = "140b41b22a29beb4061bda66b6747e14";
        byte[] keyArr = Hex.decodeHex(key);
        String plainText = "Basic CBC mode encryption needs padding and random iv";
        byte[] plainTextArr = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encoded = AESUtils.encryptCBC(keyArr, plainTextArr, null);
        byte[] decoded = AESUtils.decryptCBC(keyArr, encoded);
        Assertions.assertEquals(plainText, new String(decoded));
    }

    @Test
    void testAesCTREncrypt() throws Exception {
        String key = "36f18357be4dbd77f050515c73fcf9f2";
        byte[] keyArr = Hex.decodeHex(key);
        String cypherText = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";
        String plainText = "CTR mode lets you build a stream cipher from a block cipher.";
        byte[] cypherTextArr = Hex.decodeHex(cypherText);
        byte[] iv = Arrays.copyOfRange(cypherTextArr, 0, 16);
        byte[] plainTextArr = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encoded = AESUtils.encryptCTR(keyArr, plainTextArr, iv);
        Assertions.assertEquals(cypherText, Hex.encodeHexString(encoded));
    }

    @Test
    void testAesCTRDecrypt() throws Exception {
        String key = "36f18357be4dbd77f050515c73fcf9f2";
        byte[] keyArr = Hex.decodeHex(key);
        String cypherText = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";
        byte[] cypherTextArr = Hex.decodeHex(cypherText);
        String plainText = "CTR mode lets you build a stream cipher from a block cipher.";
        byte[] decoded = AESUtils.decryptCTR(keyArr, cypherTextArr);
        Assertions.assertEquals(plainText, new String(decoded));
    }

    @Test
    void testAesCTREncDec() throws Exception {
        String key = "36f18357be4dbd77f050515c73fcf9f2";
        byte[] keyArr = Hex.decodeHex(key);
        String plainText = "CTR mode lets you build a stream cipher from a block cipher with random iv";
        byte[] plainTextArr = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encoded = AESUtils.encryptCTR(keyArr, plainTextArr, null);
        byte[] decoded = AESUtils.decryptCTR(keyArr, encoded);
        Assertions.assertEquals(plainText, new String(decoded));
    }

}