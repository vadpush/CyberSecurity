package ru.mipt.cybersecurity.crypto.ec;

import ru.mipt.cybersecurity.crypto.CipherParameters;
import ru.mipt.cybersecurity.math.ec.ECPoint;

public interface ECEncryptor
{
    void init(CipherParameters params);

    ECPair encrypt(ECPoint point);
}
