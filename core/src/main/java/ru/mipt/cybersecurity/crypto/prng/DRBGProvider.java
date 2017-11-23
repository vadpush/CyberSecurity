package ru.mipt.cybersecurity.crypto.prng;

import ru.mipt.cybersecurity.crypto.prng.drbg.SP80090DRBG;

interface DRBGProvider
{
    SP80090DRBG get(EntropySource entropySource);
}
