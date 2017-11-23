package ru.mipt.cybersecurity.crypto.tls;

public interface TlsPSKIdentityManager
{
    byte[] getHint();

    byte[] getPSK(byte[] identity);
}
