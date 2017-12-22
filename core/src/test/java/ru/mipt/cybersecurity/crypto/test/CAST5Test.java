package ru.mipt.cybersecurity.crypto.test;

import ru.mipt.cybersecurity.crypto.engines.CAST5Engine;
import ru.mipt.cybersecurity.crypto.params.KeyParameter;
import ru.mipt.cybersecurity.util.encoders.Hex;
import ru.mipt.cybersecurity.util.test.SimpleTest;

/**
 * cast tester - vectors from http://www.ietf.org/rfc/rfc2144.txt
 */
public class CAST5Test
    extends CipherTest
{
    static SimpleTest[]  tests = {
        new BlockCipherVectorTest(0, new CAST5Engine(),
            new KeyParameter(Hex.decode("0123456712345678234567893456789A")),
            "0123456789ABCDEF", 
            "238B4FE5847E44B2"),
        new BlockCipherVectorTest(0, new CAST5Engine(),
            new KeyParameter(Hex.decode("01234567123456782345")),
            "0123456789ABCDEF", 
            "EB6A711A2C02271B"),
        new BlockCipherVectorTest(0, new CAST5Engine(),
            new KeyParameter(Hex.decode("0123456712")),
            "0123456789ABCDEF", 
            "7Ac816d16E9B302E"),
            };

    CAST5Test()
    {
        super(tests, new CAST5Engine(), new KeyParameter(new byte[16]));
    }

    public String getName()
    {
        return "CAST5";
    }

    public static void main(
        String[]    args)
    {
        runTest(new CAST5Test());
    }
}
