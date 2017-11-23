package ru.mipt.cybersecurity.pqc.crypto.test;


import java.math.BigInteger;
import java.security.SecureRandom;

import ru.mipt.cybersecurity.crypto.AsymmetricCipherKeyPair;
import ru.mipt.cybersecurity.crypto.digests.SHA224Digest;
import ru.mipt.cybersecurity.crypto.params.ParametersWithRandom;
import ru.mipt.cybersecurity.pqc.crypto.DigestingMessageSigner;
import ru.mipt.cybersecurity.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
import ru.mipt.cybersecurity.pqc.crypto.rainbow.RainbowKeyPairGenerator;
import ru.mipt.cybersecurity.pqc.crypto.rainbow.RainbowParameters;
import ru.mipt.cybersecurity.pqc.crypto.rainbow.RainbowSigner;
import ru.mipt.cybersecurity.util.BigIntegers;
import ru.mipt.cybersecurity.util.test.SimpleTest;


public class RainbowSignerTest
extends SimpleTest
{
    public String getName()
    {
        return "Rainbow";
    }

    public void performTest()
    {
        RainbowParameters params = new RainbowParameters();

        RainbowKeyPairGenerator rainbowKeyGen = new RainbowKeyPairGenerator();
        RainbowKeyGenerationParameters genParam = new RainbowKeyGenerationParameters(new SecureRandom(), params);

        rainbowKeyGen.init(genParam);

        AsymmetricCipherKeyPair pair = rainbowKeyGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), new SecureRandom());

        DigestingMessageSigner rainbowSigner = new DigestingMessageSigner(new RainbowSigner() , new SHA224Digest());

        rainbowSigner.init(true, param);

        byte[] message = BigIntegers.asUnsignedByteArray(new BigInteger("968236873715988614170569073515315707566766479517"));
        rainbowSigner.update(message, 0, message.length);
        byte[] sig = rainbowSigner.generateSignature();

        rainbowSigner.init(false, pair.getPublic());
        rainbowSigner.update(message, 0, message.length);

        if (!rainbowSigner.verifySignature(sig))
        {
            fail("verification fails");
        }
    }

    public static void main(
            String[]    args)
    {
        runTest(new RainbowSignerTest());
    }
}
