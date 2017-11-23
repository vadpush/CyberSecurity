package ru.mipt.cybersecurity.jcajce.provider.symmetric;

import ru.mipt.cybersecurity.crypto.CipherKeyGenerator;
import ru.mipt.cybersecurity.crypto.engines.ChaCha7539Engine;
import ru.mipt.cybersecurity.crypto.engines.ChaChaEngine;
import ru.mipt.cybersecurity.jcajce.provider.config.ConfigurableProvider;
import ru.mipt.cybersecurity.jcajce.provider.symmetric.util.BaseKeyGenerator;
import ru.mipt.cybersecurity.jcajce.provider.symmetric.util.BaseStreamCipher;
import ru.mipt.cybersecurity.jcajce.provider.util.AlgorithmProvider;

public final class ChaCha
{
    private ChaCha()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new ChaChaEngine(), 8);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("ChaCha", 128, new CipherKeyGenerator());
        }
    }

    public static class Base7539
        extends BaseStreamCipher
    {
        public Base7539()
        {
            super(new ChaCha7539Engine(), 12);
        }
    }

    public static class KeyGen7539
        extends BaseKeyGenerator
    {
        public KeyGen7539()
        {
            super("ChaCha7539", 256, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = ChaCha.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.CHACHA", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.CHACHA", PREFIX + "$KeyGen");

            provider.addAlgorithm("Cipher.CHACHA7539", PREFIX + "$Base7539");
            provider.addAlgorithm("KeyGenerator.CHACHA7539", PREFIX + "$KeyGen7539");
        }
    }
}
