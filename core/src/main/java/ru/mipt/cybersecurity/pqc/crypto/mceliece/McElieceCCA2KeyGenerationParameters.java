package ru.mipt.cybersecurity.pqc.crypto.mceliece;

import java.security.SecureRandom;

import ru.mipt.cybersecurity.crypto.KeyGenerationParameters;

public class McElieceCCA2KeyGenerationParameters
    extends KeyGenerationParameters
{
    private McElieceCCA2Parameters params;

    public McElieceCCA2KeyGenerationParameters(
        SecureRandom random,
        McElieceCCA2Parameters params)
    {
        // XXX key size?
        super(random, 128);
        this.params = params;
    }

    public McElieceCCA2Parameters getParameters()
    {
        return params;
    }
}