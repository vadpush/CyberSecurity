package ru.mipt.cybersecurity.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import ru.mipt.cybersecurity.crypto.AsymmetricCipherKeyPair;
import ru.mipt.cybersecurity.crypto.AsymmetricCipherKeyPairGenerator;
import ru.mipt.cybersecurity.crypto.KeyGenerationParameters;
import ru.mipt.cybersecurity.crypto.params.ECDomainParameters;
import ru.mipt.cybersecurity.crypto.params.ECKeyGenerationParameters;
import ru.mipt.cybersecurity.crypto.params.ECPrivateKeyParameters;
import ru.mipt.cybersecurity.crypto.params.ECPublicKeyParameters;
import ru.mipt.cybersecurity.math.ec.ECConstants;
import ru.mipt.cybersecurity.math.ec.ECMultiplier;
import ru.mipt.cybersecurity.math.ec.ECPoint;
import ru.mipt.cybersecurity.math.ec.FixedPointCombMultiplier;
import ru.mipt.cybersecurity.math.ec.WNafUtil;

public class ECKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator, ECConstants
{
    ECDomainParameters  params;
    SecureRandom        random;

    public void init(
        KeyGenerationParameters param)
    {
        ECKeyGenerationParameters  ecP = (ECKeyGenerationParameters)param;

        this.random = ecP.getRandom();
        this.params = ecP.getDomainParameters();

        if (this.random == null)
        {
            this.random = new SecureRandom();
        }
    }

    /**
     * Given the domain parameters this routine generates an EC key
     * pair in accordance with X9.62 section 5.2.1 pages 26, 27.
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigInteger n = params.getN();
        int nBitLength = n.bitLength();
        int minWeight = nBitLength >>> 2;

        BigInteger d;
        for (;;)
        {
            d = new BigInteger(nBitLength, random);

            if (d.compareTo(TWO) < 0  || (d.compareTo(n) >= 0))
            {
                continue;
            }

            if (WNafUtil.getNafWeight(d) < minWeight)
            {
                continue;
            }

            break;
        }

        ECPoint Q = createBasePointMultiplier().multiply(params.getG(), d);

        return new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(Q, params),
            new ECPrivateKeyParameters(d, params));
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
