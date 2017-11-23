package ru.mipt.cybersecurity.crypto.ec;

import ru.mipt.cybersecurity.crypto.CipherParameters;
import ru.mipt.cybersecurity.math.ec.ECPoint;

public interface ECDecryptor
{
    void init(CipherParameters params);

    ECPoint decrypt(ECPair cipherText);
}
