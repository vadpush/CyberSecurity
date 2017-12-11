package ru.mipt.cybersecurity.pqc.jcajce.provider;

import ru.mipt.cybersecurity.jcajce.provider.config.ConfigurableProvider;
import ru.mipt.cybersecurity.jcajce.provider.util.AsymmetricAlgorithmProvider;
import ru.mipt.cybersecurity.jcajce.provider.util.AsymmetricKeyInfoConverter;
import ru.mipt.cybersecurity.pqc.asn1.PQCObjectIdentifiers;
import ru.mipt.cybersecurity.pqc.jcajce.provider.newhope.NHKeyFactorySpi;

public class NH
{
    private static final String PREFIX = "ru.mipt.cybersecurity.jcajce.provider" + ".newhope.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.NH", PREFIX + "NHKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.NH", PREFIX + "NHKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyAgreement.NH", PREFIX + "KeyAgreementSpi");

            AsymmetricKeyInfoConverter keyFact = new NHKeyFactorySpi();

            registerOid(provider, PQCObjectIdentifiers.newHope, "NH", keyFact);
        }
    }
}
