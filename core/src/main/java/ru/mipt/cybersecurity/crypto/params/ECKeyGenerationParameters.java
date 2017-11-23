package ru.mipt.cybersecurity.crypto.params;

import java.security.SecureRandom;

import ru.mipt.cybersecurity.crypto.KeyGenerationParameters;

public class ECKeyGenerationParameters
    extends KeyGenerationParameters
{
    private ECDomainParameters  domainParams;

    public ECKeyGenerationParameters(
        ECDomainParameters      domainParams,
        SecureRandom            random)
    {
        super(random, domainParams.getN().bitLength());

        this.domainParams = domainParams;
    }

    public ECDomainParameters getDomainParameters()
    {
        return domainParams;
    }
}
