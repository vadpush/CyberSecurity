package ru.mipt.cybersecurity.crypto.test;

import java.security.SecureRandom;

import ru.mipt.cybersecurity.asn1.sec.SECNamedCurves;
import ru.mipt.cybersecurity.asn1.x9.X9ECParameters;
import ru.mipt.cybersecurity.crypto.AsymmetricCipherKeyPair;
import ru.mipt.cybersecurity.crypto.digests.SHA1Digest;
import ru.mipt.cybersecurity.crypto.generators.ECKeyPairGenerator;
import ru.mipt.cybersecurity.crypto.generators.KDF2BytesGenerator;
import ru.mipt.cybersecurity.crypto.kems.ECIESKeyEncapsulation;
import ru.mipt.cybersecurity.crypto.params.ECDomainParameters;
import ru.mipt.cybersecurity.crypto.params.ECKeyGenerationParameters;
import ru.mipt.cybersecurity.crypto.params.KeyParameter;
import ru.mipt.cybersecurity.util.test.SimpleTest;

/**
 * Tests for the ECIES Key Encapsulation Mechanism
 */
public class ECIESKeyEncapsulationTest
    extends SimpleTest
{
    public String getName()
    {
        return "ECIESKeyEncapsulation";
    }

    public void performTest()
        throws Exception
    {
        
        // Set EC domain parameters and generate key pair
        X9ECParameters            spec     = SECNamedCurves.getByName("secp224r1");
        ECDomainParameters        ecDomain = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
        ECKeyPairGenerator        ecGen    = new ECKeyPairGenerator();

        ecGen.init(new ECKeyGenerationParameters(ecDomain, new SecureRandom()));

        AsymmetricCipherKeyPair    keys      = ecGen.generateKeyPair();
        
        // Set ECIES-KEM parameters
        ECIESKeyEncapsulation     kem;
        KDF2BytesGenerator        kdf = new KDF2BytesGenerator(new SHA1Digest());
        SecureRandom            rnd = new SecureRandom();
        byte[]                    out = new byte[57];
        KeyParameter            key1, key2;
        
        // Test basic ECIES-KEM
        kem = new ECIESKeyEncapsulation(kdf, rnd);
        
        kem.init(keys.getPublic());
        key1 = (KeyParameter)kem.encrypt(out, 128);
        
        kem.init(keys.getPrivate());
        key2 = (KeyParameter)kem.decrypt(out, 128);

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed basic test");
        }

        // Test ECIES-KEM using new cofactor mode
        kem = new ECIESKeyEncapsulation(kdf, rnd, true, false, false);
        
        kem.init(keys.getPublic());
        key1 = (KeyParameter)kem.encrypt(out, 128);
        
        kem.init(keys.getPrivate());
        key2 = (KeyParameter)kem.decrypt(out, 128);

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed cofactor test");
        }

        // Test ECIES-KEM using old cofactor mode
        kem = new ECIESKeyEncapsulation(kdf, rnd, false, true, false);
        
        kem.init(keys.getPublic());
        key1 = (KeyParameter)kem.encrypt(out, 128);
    
        kem.init(keys.getPrivate());
        key2 = (KeyParameter)kem.decrypt(out, 128);

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed old cofactor test");
        }

        // Test ECIES-KEM using single hash mode
        kem = new ECIESKeyEncapsulation(kdf, rnd, false, false, true);
        
        kem.init(keys.getPublic());
        key1 = (KeyParameter)kem.encrypt(out, 128);
        
        kem.init(keys.getPrivate());
        key2 = (KeyParameter)kem.decrypt(out, 128);

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed single hash test");
        }

        // Test ECIES-KEM using new cofactor mode and single hash mode
        kem = new ECIESKeyEncapsulation(kdf, rnd, true, false, true);
        
        kem.init(keys.getPublic());
        key1 = (KeyParameter)kem.encrypt(out, 128);
        
        kem.init(keys.getPrivate());
        key2 = (KeyParameter)kem.decrypt(out, 128);

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed cofactor and single hash test");
        }

        // Test ECIES-KEM using old cofactor mode and single hash mode
        kem = new ECIESKeyEncapsulation(kdf, rnd, false, true, true);
        
        kem.init(keys.getPublic());
        key1 = (KeyParameter)kem.encrypt(out, 128);
        
        kem.init(keys.getPrivate());
        key2 = (KeyParameter)kem.decrypt(out, 128);

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed old cofactor and single hash test");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new ECIESKeyEncapsulationTest());
    }
}
