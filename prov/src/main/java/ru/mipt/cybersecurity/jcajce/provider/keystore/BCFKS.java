package ru.mipt.cybersecurity.jcajce.provider.keystore;

import ru.mipt.cybersecurity.jcajce.provider.config.ConfigurableProvider;
import ru.mipt.cybersecurity.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class BCFKS
{
    private static final String PREFIX = "ru.mipt.cybersecurity.jcajce.provider.keystore" + ".bcfks.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyStore.BCFKS", PREFIX + "BcFKSKeyStoreSpi$Std");
            provider.addAlgorithm("KeyStore.BCFKS-DEF", PREFIX + "BcFKSKeyStoreSpi$Def");
        }
    }
}
