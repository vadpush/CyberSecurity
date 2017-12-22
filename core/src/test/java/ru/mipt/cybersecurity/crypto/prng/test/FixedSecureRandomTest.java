package ru.mipt.cybersecurity.crypto.prng.test;

import ru.mipt.cybersecurity.crypto.prng.FixedSecureRandom;
import ru.mipt.cybersecurity.util.Arrays;
import ru.mipt.cybersecurity.util.encoders.Hex;
import ru.mipt.cybersecurity.util.test.SimpleTest;

public class FixedSecureRandomTest
    extends SimpleTest
{
    byte[]  base = Hex.decode("deadbeefdeadbeef");
    byte[]  r1 = Hex.decode("cafebabecafebabe");
    byte[]  r2 = Hex.decode("ffffffffcafebabedeadbeef");

    public String getName()
    {
        return "FixedSecureRandom";
    }

    public void performTest()
        throws Exception
    {
        FixedSecureRandom fixed = new FixedSecureRandom(base);
        byte[]       buf = new byte[8];

        fixed.nextBytes(buf);

        if (!Arrays.areEqual(buf, base))
        {
            fail("wrong data returned");
        }

        fixed = new FixedSecureRandom(base);

        byte[] seed = fixed.generateSeed(8);

        if (!Arrays.areEqual(seed, base))
        {
            fail("wrong seed data returned");
        }

        if (!fixed.isExhausted())
        {
            fail("not exhausted");
        }

        fixed = new FixedSecureRandom(new byte[][] { r1, r2 });

        seed = fixed.generateSeed(12);

        if (!Arrays.areEqual(seed, Hex.decode("cafebabecafebabeffffffff")))
        {
            fail("wrong seed data returned - composite");
        }

        fixed.nextBytes(buf);

        if (!Arrays.areEqual(buf, Hex.decode("cafebabedeadbeef")))
        {
            fail("wrong data returned");
        }
    }

    public static void main(String[] args)
    {
        runTest(new FixedSecureRandomTest());
    }
}
