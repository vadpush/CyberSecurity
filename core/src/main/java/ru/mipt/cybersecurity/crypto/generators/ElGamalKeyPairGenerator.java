package ru.mipt.cybersecurity.crypto.generators;

import java.math.BigInteger;

import ru.mipt.cybersecurity.crypto.AsymmetricCipherKeyPair;
import ru.mipt.cybersecurity.crypto.AsymmetricCipherKeyPairGenerator;
import ru.mipt.cybersecurity.crypto.KeyGenerationParameters;
import ru.mipt.cybersecurity.crypto.params.DHParameters;
import ru.mipt.cybersecurity.crypto.params.ElGamalKeyGenerationParameters;
import ru.mipt.cybersecurity.crypto.params.ElGamalParameters;
import ru.mipt.cybersecurity.crypto.params.ElGamalPrivateKeyParameters;
import ru.mipt.cybersecurity.crypto.params.ElGamalPublicKeyParameters;

/**
 * a ElGamal key pair generator.
 * <p>
 * This generates keys consistent for use with ElGamal as described in
 * page 164 of "Handbook of Applied Cryptography".
 */
public class ElGamalKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private ElGamalKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (ElGamalKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
        ElGamalParameters egp = param.getParameters();
        DHParameters dhp = new DHParameters(egp.getP(), egp.getG(), null, egp.getL());  

        BigInteger x = helper.calculatePrivate(dhp, param.getRandom()); 
        BigInteger y = helper.calculatePublic(dhp, x);

        return new AsymmetricCipherKeyPair(
            new ElGamalPublicKeyParameters(y, egp),
            new ElGamalPrivateKeyParameters(x, egp));
    }
}
