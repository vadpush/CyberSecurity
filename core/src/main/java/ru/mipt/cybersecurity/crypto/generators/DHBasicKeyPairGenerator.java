package ru.mipt.cybersecurity.crypto.generators;

import ru.mipt.cybersecurity.crypto.AsymmetricCipherKeyPair;
import ru.mipt.cybersecurity.crypto.AsymmetricCipherKeyPairGenerator;
import ru.mipt.cybersecurity.crypto.KeyGenerationParameters;
import ru.mipt.cybersecurity.crypto.params.DHKeyGenerationParameters;
import ru.mipt.cybersecurity.crypto.params.DHParameters;
import ru.mipt.cybersecurity.crypto.params.DHPrivateKeyParameters;
import ru.mipt.cybersecurity.crypto.params.DHPublicKeyParameters;

import java.math.BigInteger;

/**
 * a basic Diffie-Hellman key pair generator.
 *
 * This generates keys consistent for use with the basic algorithm for
 * Diffie-Hellman.
 */
public class DHBasicKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private DHKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (DHKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
        DHParameters dhp = param.getParameters();

        BigInteger x = helper.calculatePrivate(dhp, param.getRandom()); 
        BigInteger y = helper.calculatePublic(dhp, x);

        return new AsymmetricCipherKeyPair(
            new DHPublicKeyParameters(y, dhp),
            new DHPrivateKeyParameters(x, dhp));
    }
}
