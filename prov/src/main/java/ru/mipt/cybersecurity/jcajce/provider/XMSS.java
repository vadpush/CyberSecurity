package ru.mipt.cybersecurity.pqc.jcajce.provider;

import ru.mipt.cybersecurity.asn1.bc.BCObjectIdentifiers;
import ru.mipt.cybersecurity.jcajce.provider.config.ConfigurableProvider;
import ru.mipt.cybersecurity.jcajce.provider.util.AsymmetricAlgorithmProvider;
import ru.mipt.cybersecurity.pqc.asn1.PQCObjectIdentifiers;
import ru.mipt.cybersecurity.pqc.jcajce.provider.xmss.XMSSKeyFactorySpi;
import ru.mipt.cybersecurity.pqc.jcajce.provider.xmss.XMSSMTKeyFactorySpi;

public class XMSS
{
    private static final String PREFIX = "ru.mipt.cybersecurity.jcajce.provider" + ".xmss.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.XMSS", PREFIX + "XMSSKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.XMSS", PREFIX + "XMSSKeyPairGeneratorSpi");

            addSignatureAlgorithm(provider, "SHA256", "XMSS", PREFIX + "XMSSSignatureSpi$withSha256", BCObjectIdentifiers.xmss_with_SHA256);
            addSignatureAlgorithm(provider, "SHAKE128", "XMSS", PREFIX + "XMSSSignatureSpi$withShake128", BCObjectIdentifiers.xmss_with_SHAKE128);
            addSignatureAlgorithm(provider, "SHA512", "XMSS", PREFIX + "XMSSSignatureSpi$withSha512", BCObjectIdentifiers.xmss_with_SHA512);
            addSignatureAlgorithm(provider, "SHAKE256", "XMSS", PREFIX + "XMSSSignatureSpi$withShake256", BCObjectIdentifiers.xmss_with_SHAKE256);

            provider.addAlgorithm("KeyFactory.XMSSMT", PREFIX + "XMSSMTKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.XMSSMT", PREFIX + "XMSSMTKeyPairGeneratorSpi");

            addSignatureAlgorithm(provider, "SHA256", "XMSSMT", PREFIX + "XMSSMTSignatureSpi$withSha256", BCObjectIdentifiers.xmss_mt_with_SHA256);
            addSignatureAlgorithm(provider, "SHAKE128", "XMSSMT", PREFIX + "XMSSMTSignatureSpi$withShake128", BCObjectIdentifiers.xmss_mt_with_SHAKE128);
            addSignatureAlgorithm(provider, "SHA512", "XMSSMT", PREFIX + "XMSSMTSignatureSpi$withSha512", BCObjectIdentifiers.xmss_mt_with_SHA512);
            addSignatureAlgorithm(provider, "SHAKE256", "XMSSMT", PREFIX + "XMSSMTSignatureSpi$withShake256", BCObjectIdentifiers.xmss_mt_with_SHAKE256);

            registerOid(provider, PQCObjectIdentifiers.xmss, "XMSS", new XMSSKeyFactorySpi());
            registerOid(provider, PQCObjectIdentifiers.xmss_mt, "XMSSMT", new XMSSMTKeyFactorySpi());
        }
    }
}
