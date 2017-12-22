package ru.mipt.cybersecurity.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import ru.mipt.cybersecurity.crypto.AsymmetricCipherKeyPair;
import ru.mipt.cybersecurity.crypto.digests.SHA1Digest;
import ru.mipt.cybersecurity.crypto.generators.KDF2BytesGenerator;
import ru.mipt.cybersecurity.crypto.generators.RSAKeyPairGenerator;
import ru.mipt.cybersecurity.crypto.kems.RSAKeyEncapsulation;
import ru.mipt.cybersecurity.crypto.params.KeyParameter;
import ru.mipt.cybersecurity.crypto.params.RSAKeyGenerationParameters;
import ru.mipt.cybersecurity.util.test.SimpleTest;

/**
 * Tests for the RSA Key Encapsulation Mechanism
 */
public class RSAKeyEncapsulationTest
    extends SimpleTest
{
    public String getName()
    {
        return "RSAKeyEncapsulation";
    }

    public void performTest()
        throws Exception
    {
        // Generate RSA key pair
        RSAKeyPairGenerator        rsaGen = new RSAKeyPairGenerator();
        rsaGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 1024, 5));
        AsymmetricCipherKeyPair    keys   = rsaGen.generateKeyPair();
        
        // Set RSA-KEM parameters
        RSAKeyEncapsulation     kem;
        KDF2BytesGenerator        kdf = new KDF2BytesGenerator(new SHA1Digest());
        SecureRandom            rnd = new SecureRandom();
        byte[]                    out = new byte[128];
        KeyParameter            key1, key2;
        
        // Test RSA-KEM
        kem = new RSAKeyEncapsulation(kdf, rnd);
        
        kem.init(keys.getPublic());
        key1 = (KeyParameter)kem.encrypt(out, 128);
        
        kem.init(keys.getPrivate());
        key2 = (KeyParameter)kem.decrypt(out, 128);

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed test");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new RSAKeyEncapsulationTest());
    }
}
