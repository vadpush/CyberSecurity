package ru.mipt.cybersecurity.jcajce.provider.symmetric;

import ru.mipt.cybersecurity.crypto.CipherKeyGenerator;
import ru.mipt.cybersecurity.crypto.engines.VMPCKSA3Engine;
import ru.mipt.cybersecurity.jcajce.provider.config.ConfigurableProvider;
import ru.mipt.cybersecurity.jcajce.provider.symmetric.util.BaseKeyGenerator;
import ru.mipt.cybersecurity.jcajce.provider.symmetric.util.BaseStreamCipher;
import ru.mipt.cybersecurity.jcajce.provider.util.AlgorithmProvider;

public final class VMPCKSA3
{
    private VMPCKSA3()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new VMPCKSA3Engine(), 16);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("VMPC-KSA3", 128, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = VMPCKSA3.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.VMPC-KSA3", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.VMPC-KSA3", PREFIX + "$KeyGen");

        }
    }
}
