package ru.mipt.cybersecurity.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import ru.mipt.cybersecurity.asn1.gm.GMObjectIdentifiers;
import ru.mipt.cybersecurity.jcajce.provider.config.ConfigurableProvider;
import ru.mipt.cybersecurity.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class GM
{
    private static final String PREFIX = "ru.mipt.cybersecurity.jcajce.provider.asymmetric" + ".ec.";

    private static final Map<String, String> generalSm2Attributes = new HashMap<String, String>();

    static
    {
        generalSm2Attributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        generalSm2Attributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Signature.SM3WITHSM2", PREFIX + "GMSignatureSpi$sm3WithSM2");
            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_sm3, "SM3WITHSM2");
        }
    }
}
