package ru.mipt.cybersecurity.crypto.engines;

import java.util.Enumeration;
import java.util.Hashtable;

import ru.mipt.cybersecurity.crypto.BlockCipher;
import ru.mipt.cybersecurity.crypto.CipherParameters;
import ru.mipt.cybersecurity.crypto.DataLengthException;
import ru.mipt.cybersecurity.crypto.OutputLengthException;
import ru.mipt.cybersecurity.crypto.params.KeyParameter;
import ru.mipt.cybersecurity.crypto.params.ParametersWithSBox;
import ru.mipt.cybersecurity.util.Arrays;
import ru.mipt.cybersecurity.util.Strings;

/**
 * implementation of Kuznyechik, GOST 28147-14
 */


public class Kuznyechik     implements BlockCipher
{


    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {

    }

    public String getAlgorithmName() {
        return null;
    }

    public int getBlockSize() {
        return 0;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        return 0;
    }

    public void reset() {

    }
}
