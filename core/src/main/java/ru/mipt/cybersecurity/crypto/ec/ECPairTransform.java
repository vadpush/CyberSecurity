package ru.mipt.cybersecurity.crypto.ec;

import ru.mipt.cybersecurity.crypto.CipherParameters;

public interface ECPairTransform
{
    void init(CipherParameters params);

    ECPair transform(ECPair cipherText);
}
