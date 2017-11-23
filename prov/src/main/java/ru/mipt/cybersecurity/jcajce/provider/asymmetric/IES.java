package ru.mipt.cybersecurity.jcajce.provider.asymmetric;

import ru.mipt.cybersecurity.jcajce.provider.config.ConfigurableProvider;
import ru.mipt.cybersecurity.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class IES
{
    private static final String PREFIX = "ru.mipt.cybersecurity.jcajce.provider.asymmetric" + ".ies.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("AlgorithmParameters.IES", PREFIX + "AlgorithmParametersSpi");
            provider.addAlgorithm("AlgorithmParameters.ECIES", PREFIX + "AlgorithmParametersSpi");
        }
    }
}
