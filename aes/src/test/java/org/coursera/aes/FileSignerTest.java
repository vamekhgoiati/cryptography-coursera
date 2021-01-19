package org.coursera.aes;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;

class FileSignerTest {

    @Test
    void testSign() throws Exception {
        File file = new File(getClass().getClassLoader().getResource("6.2.birthday.mp4_download").toURI());
        Assertions.assertEquals("03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8", Hex.encodeHexString(FileSigner.sign(file)));
    }

}