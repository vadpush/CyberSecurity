package ru.mipt.cybersecurity.jcajce.provider.symmetric.util;

import ru.mipt.cybersecurity.crypto.BlockCipher;

public interface BlockCipherProvider
{
    BlockCipher get();
}
