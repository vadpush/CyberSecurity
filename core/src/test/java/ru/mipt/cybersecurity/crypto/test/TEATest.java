package ru.mipt.cybersecurity.crypto.test;

import ru.mipt.cybersecurity.crypto.engines.TEAEngine;
import ru.mipt.cybersecurity.crypto.params.KeyParameter;
import ru.mipt.cybersecurity.util.encoders.Hex;
import ru.mipt.cybersecurity.util.test.SimpleTest;

/**
 * TEA tester - based on C implementation results from http://www.simonshepherd.supanet.com/tea.htm
 */
public class TEATest
    extends CipherTest
{
    static SimpleTest[]  tests = {
        new BlockCipherVectorTest(0, new TEAEngine(),
            new KeyParameter(Hex.decode("00000000000000000000000000000000")),
            "0000000000000000",
            "41ea3a0a94baa940"),
        new BlockCipherVectorTest(1, new TEAEngine(),
            new KeyParameter(Hex.decode("00000000000000000000000000000000")),
            "0102030405060708",
            "6a2f9cf3fccf3c55"),
        new BlockCipherVectorTest(2, new TEAEngine(),
            new KeyParameter(Hex.decode("0123456712345678234567893456789A")),
            "0000000000000000",
            "34e943b0900f5dcb"),
        new BlockCipherVectorTest(3, new TEAEngine(),
            new KeyParameter(Hex.decode("0123456712345678234567893456789A")),
            "0102030405060708",
            "773dc179878a81c0"),
            };

    TEATest()
    {
        super(tests, new TEAEngine(), new KeyParameter(new byte[16]));
    }

    public String getName()
    {
        return "TEA";
    }

    public static void main(
        String[]    args)
    {
        runTest(new TEATest());
    }
}
