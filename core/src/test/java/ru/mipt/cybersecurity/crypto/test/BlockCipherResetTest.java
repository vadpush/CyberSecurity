package ru.mipt.cybersecurity.crypto.test;

import ru.mipt.cybersecurity.crypto.BlockCipher;
import ru.mipt.cybersecurity.crypto.CipherParameters;
import ru.mipt.cybersecurity.crypto.DataLengthException;
import ru.mipt.cybersecurity.crypto.InvalidCipherTextException;
import ru.mipt.cybersecurity.crypto.engines.AESEngine;
import ru.mipt.cybersecurity.crypto.engines.AESFastEngine;
import ru.mipt.cybersecurity.crypto.engines.AESLightEngine;
import ru.mipt.cybersecurity.crypto.engines.BlowfishEngine;
import ru.mipt.cybersecurity.crypto.engines.CAST5Engine;
import ru.mipt.cybersecurity.crypto.engines.CAST6Engine;
import ru.mipt.cybersecurity.crypto.engines.DESEngine;
import ru.mipt.cybersecurity.crypto.engines.DESedeEngine;
import ru.mipt.cybersecurity.crypto.engines.NoekeonEngine;
import ru.mipt.cybersecurity.crypto.engines.RC6Engine;
import ru.mipt.cybersecurity.crypto.engines.SEEDEngine;
import ru.mipt.cybersecurity.crypto.engines.SerpentEngine;
import ru.mipt.cybersecurity.crypto.engines.TEAEngine;
import ru.mipt.cybersecurity.crypto.engines.TwofishEngine;
import ru.mipt.cybersecurity.crypto.engines.XTEAEngine;
import ru.mipt.cybersecurity.crypto.modes.CBCBlockCipher;
import ru.mipt.cybersecurity.crypto.modes.CFBBlockCipher;
import ru.mipt.cybersecurity.crypto.modes.GOFBBlockCipher;
import ru.mipt.cybersecurity.crypto.modes.OFBBlockCipher;
import ru.mipt.cybersecurity.crypto.modes.OpenPGPCFBBlockCipher;
import ru.mipt.cybersecurity.crypto.modes.PGPCFBBlockCipher;
import ru.mipt.cybersecurity.crypto.modes.SICBlockCipher;
import ru.mipt.cybersecurity.crypto.params.KeyParameter;
import ru.mipt.cybersecurity.crypto.params.ParametersWithIV;
import ru.mipt.cybersecurity.util.Arrays;
import ru.mipt.cybersecurity.util.encoders.Hex;
import ru.mipt.cybersecurity.util.test.SimpleTest;

/**
 * Test whether block ciphers implement reset contract on init, encrypt/decrypt and reset.
 */
public class BlockCipherResetTest
    extends SimpleTest
{

    public String getName()
    {
        return "Block Cipher Reset";
    }

    public void performTest()
        throws Exception
    {
        // 128 bit block ciphers
        testReset("AESFastEngine", new AESFastEngine(), new AESFastEngine(), new KeyParameter(new byte[16]));
        testReset("AESEngine", new AESEngine(), new AESEngine(), new KeyParameter(new byte[16]));
        testReset("AESLightEngine", new AESLightEngine(), new AESLightEngine(), new KeyParameter(new byte[16]));
        testReset("Twofish", new TwofishEngine(), new TwofishEngine(), new KeyParameter(new byte[16]));
        testReset("NoekeonEngine", new NoekeonEngine(), new NoekeonEngine(), new KeyParameter(new byte[16]));
        testReset("SerpentEngine", new SerpentEngine(), new SerpentEngine(), new KeyParameter(new byte[16]));
        testReset("SEEDEngine", new SEEDEngine(), new SEEDEngine(), new KeyParameter(new byte[16]));
        testReset("CAST6Engine", new CAST6Engine(), new CAST6Engine(), new KeyParameter(new byte[16]));
        testReset("RC6Engine", new RC6Engine(), new RC6Engine(), new KeyParameter(new byte[16]));

        // 64 bit block ciphers
        testReset("DESEngine", new DESEngine(), new DESEngine(), new KeyParameter(new byte[8]));
        testReset("BlowfishEngine", new BlowfishEngine(), new BlowfishEngine(), new KeyParameter(new byte[8]));
        testReset("CAST5Engine", new CAST5Engine(), new CAST5Engine(), new KeyParameter(new byte[8]));
        testReset("DESedeEngine", new DESedeEngine(), new DESedeEngine(), new KeyParameter(new byte[24]));
        testReset("TEAEngine", new TEAEngine(), new TEAEngine(), new KeyParameter(new byte[16]));
        testReset("XTEAEngine", new XTEAEngine(), new XTEAEngine(), new KeyParameter(new byte[16]));

        // primitive block cipher modes (don't reset on processBlock)
        testModeReset("AES/CBC", new CBCBlockCipher(new AESEngine()), new CBCBlockCipher(new AESEngine()),
            new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
        testModeReset("AES/SIC", new SICBlockCipher(new AESEngine()), new SICBlockCipher(new AESEngine()),
            new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
        testModeReset("AES/CFB", new CFBBlockCipher(new AESEngine(), 128), new CFBBlockCipher(new AESEngine(), 128),
            new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
        testModeReset("AES/OFB", new OFBBlockCipher(new AESEngine(), 128), new OFBBlockCipher(new AESEngine(), 128),
            new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
        testModeReset("AES/GCTR", new GOFBBlockCipher(new DESEngine()), new GOFBBlockCipher(new DESEngine()),
            new ParametersWithIV(new KeyParameter(new byte[8]), new byte[8]));
        testModeReset("AES/OpenPGPCFB", new OpenPGPCFBBlockCipher(new AESEngine()), new OpenPGPCFBBlockCipher(
            new AESEngine()), new KeyParameter(new byte[16]));
        testModeReset("AES/PGPCFB", new PGPCFBBlockCipher(new AESEngine(), false), new PGPCFBBlockCipher(
            new AESEngine(), false), new KeyParameter(new byte[16]));

        // PGPCFB with IV is broken (it's also not a PRP, so probably shouldn't be a BlockCipher)
        // testModeReset("AES/PGPCFBwithIV", new PGPCFBBlockCipher(new AESEngine(), true), new
        // PGPCFBBlockCipher(
        // new AESEngine(), true), new ParametersWithIV(new KeyParameter(new byte[16]), new
        // byte[16]));
        // testModeReset("AES/PGPCFBwithIV_NoIV", new PGPCFBBlockCipher(new AESEngine(), true), new
        // PGPCFBBlockCipher(
        // new AESEngine(), true), new KeyParameter(new byte[16]));

    }

    private void testModeReset(String test, BlockCipher cipher1, BlockCipher cipher2, CipherParameters params)
        throws InvalidCipherTextException
    {
        testReset(test, false, cipher1, cipher2, params);
    }

    private void testReset(String test, BlockCipher cipher1, BlockCipher cipher2, CipherParameters params)
        throws InvalidCipherTextException
    {
        testReset(test, true, cipher1, cipher2, params);
    }

    private void testReset(String test,
                           boolean testCryptReset,
                           BlockCipher cipher1,
                           BlockCipher cipher2,
                           CipherParameters params)
        throws InvalidCipherTextException
    {
        cipher1.init(true, params);

        byte[] plaintext = new byte[cipher1.getBlockSize()];
        byte[] ciphertext = new byte[(cipher1.getAlgorithmName().indexOf("PGPCFBwithIV")) > -1 ? 2 * cipher1.getBlockSize() + 2
            : cipher1.getBlockSize()];

        // Establish baseline answer
        crypt(cipher1, true, plaintext, ciphertext);

        // Test encryption resets
        checkReset(test, testCryptReset, cipher1, params, true, plaintext, ciphertext);

        // Test decryption resets with fresh instance
        cipher2.init(false, params);
        checkReset(test, testCryptReset, cipher2, params, false, ciphertext, plaintext);
    }

    private void checkReset(String test,
                            boolean testCryptReset,
                            BlockCipher cipher,
                            CipherParameters params,
                            boolean encrypt,
                            byte[] pretext,
                            byte[] posttext)
        throws InvalidCipherTextException
    {
        // Do initial run
        byte[] output = new byte[posttext.length];
        crypt(cipher, encrypt, pretext, output);

        // Check encrypt resets cipher
        if (testCryptReset)
        {
            crypt(cipher, encrypt, pretext, output);
            if (!Arrays.areEqual(output, posttext))
            {
                fail(test + (encrypt ? " encrypt" : " decrypt") + " did not reset cipher.");
            }
        }

        // Check init resets data
        cipher.processBlock(pretext, 0, output, 0);
        cipher.init(encrypt, params);

        try
        {
            crypt(cipher, encrypt, pretext, output);
        }
        catch (DataLengthException e)
        {
            fail(test + " init did not reset data.");
        }
        if (!Arrays.areEqual(output, posttext))
        {
            fail(test + " init did not reset data.", new String(Hex.encode(posttext)), new String(Hex.encode(output)));
        }

        // Check reset resets data
        cipher.processBlock(pretext, 0, output, 0);
        cipher.reset();

        try
        {
            crypt(cipher, encrypt, pretext, output);
        }
        catch (DataLengthException e)
        {
            fail(test + " reset did not reset data.");
        }
        if (!Arrays.areEqual(output, posttext))
        {
            fail(test + " reset did not reset data.");
        }
    }

    private static void crypt(BlockCipher cipher1, boolean encrypt, byte[] plaintext, byte[] output)
        throws InvalidCipherTextException
    {
        cipher1.processBlock(plaintext, 0, output, 0);
        if ((cipher1.getAlgorithmName().indexOf("PGPCFBwithIV") > -1) && !encrypt)
        {
            // Process past IV in first block
            cipher1.processBlock(plaintext, cipher1.getBlockSize(), output, 0);
        }
    }

    public static void main(String[] args)
    {
        runTest(new BlockCipherResetTest());
    }

}
