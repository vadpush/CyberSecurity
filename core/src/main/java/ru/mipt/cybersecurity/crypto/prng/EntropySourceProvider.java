package ru.mipt.cybersecurity.crypto.prng;

public interface EntropySourceProvider
{
    EntropySource get(final int bitsRequired);
}
