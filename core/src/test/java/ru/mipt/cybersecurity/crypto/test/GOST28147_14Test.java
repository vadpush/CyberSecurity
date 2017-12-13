package ru.mipt.cybersecurity.crypto.test;

import ru.mipt.cybersecurity.crypto.BlockCipher;
import ru.mipt.cybersecurity.crypto.BufferedBlockCipher;
import ru.mipt.cybersecurity.crypto.CipherParameters;
import ru.mipt.cybersecurity.crypto.engines.GOST28147Engine;
import ru.mipt.cybersecurity.crypto.engines.GOST28147_14Engine;
import ru.mipt.cybersecurity.crypto.params.KeyParameter;
import ru.mipt.cybersecurity.util.encoders.Hex;
import ru.mipt.cybersecurity.util.test.SimpleTest;

public class GOST28147_14Test extends CipherTest {
    private static char[] chInput1 = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88};
    private static char[] chOutput1 = {0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd};
    private static char[] chKey1 =
            {
                    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,0x77,
                    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
            };
    private static byte[] key1 = charsToBytes(chKey1);
    private static byte[] input1 = charsToBytes(chInput1);
    private static byte[] output1 = charsToBytes(chOutput1);

    private static byte[] charsToBytes(char[] in) {
        byte[] answ = new byte[in.length];
        for(int i = 0; i < in.length; i++)
            answ[i] = (byte)(in[i] & 0xFF);

        return answ;
    }


    static SimpleTest[]   tests =
            {,
            };


    public void performTest()
            throws Exception {
        super.performTest();

        byte[] out    = new byte[input1.length];
        //for(byte b : key1)
            //System.out.print(" b" +  b);

        //System.out.println("key1 " + key1 + " length " + key1.length);
        KeyParameter param = new KeyParameter(key1);

        //for(byte b : param.getKey())
            //System.out.print(" b" +  b);
        //System.out.println("");

        BufferedBlockCipher cipher = new BufferedBlockCipher(new GOST28147_14Engine());

        cipher.init(true, param);

        int len1 = cipher.processBytes(input1, 0, input1.length, out, 0);
        cipher.doFinal(out, len1);
        if (out.length != output1.length)
        {
            fail("failed - "
                    + "expected " + new String(Hex.encode(output1)) + " got "
                    + new String(Hex.encode(out)));
        }
        for (int i = 0; i != out.length; i++)
        {
            if (out[i] != output1[i])
            {
                fail("failed - " + "expected " + new String(Hex.encode(output1)) + " got " + new String(Hex.encode(out)));
            }
        }


        cipher = new BufferedBlockCipher(new GOST28147_14Engine());

        cipher.init(false, param);

        int len2 = cipher.processBytes(output1, 0, output1.length, out, 0);
        cipher.doFinal(out, len1);
        if (out.length != input1.length)
        {
            fail("failed - "
                    + "expected " + new String(Hex.encode(input1)) + " got "
                    + new String(Hex.encode(out)));
        }
        for (int i = 0; i != out.length; i++)
        {
            if (out[i] != input1[i])
            {
                fail("failed - " + "expected " + new String(Hex.encode(input1)) + " got " + new String(Hex.encode(out)));
            }
        }
    }

    protected GOST28147_14Test() {
        super(tests, new GOST28147Engine(), new KeyParameter(new byte[32]));
    }

    public String getName() {
        return "GOST28147-14";
    }

    public static void main(
            String[]    args)
    {
        runTest(new GOST28147_14Test());
    }
}
