package ru.mipt.cybersecurity.crypto;

import ru.mipt.cybersecurity.crypto.params.AsymmetricKeyParameter;

public interface KeyEncoder
{
    byte[] getEncoded(AsymmetricKeyParameter keyParameter);
}
