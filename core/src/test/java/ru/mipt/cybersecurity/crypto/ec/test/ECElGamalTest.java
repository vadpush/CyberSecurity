package ru.mipt.cybersecurity.crypto.ec.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import ru.mipt.cybersecurity.crypto.ec.ECDecryptor;
import ru.mipt.cybersecurity.crypto.ec.ECElGamalDecryptor;
import ru.mipt.cybersecurity.crypto.ec.ECElGamalEncryptor;
import ru.mipt.cybersecurity.crypto.ec.ECEncryptor;
import ru.mipt.cybersecurity.crypto.ec.ECPair;
import ru.mipt.cybersecurity.crypto.params.ECDomainParameters;
import ru.mipt.cybersecurity.crypto.params.ECPrivateKeyParameters;
import ru.mipt.cybersecurity.crypto.params.ECPublicKeyParameters;
import ru.mipt.cybersecurity.crypto.params.ParametersWithRandom;
import ru.mipt.cybersecurity.math.ec.ECConstants;
import ru.mipt.cybersecurity.math.ec.ECCurve;
import ru.mipt.cybersecurity.math.ec.ECPoint;
import ru.mipt.cybersecurity.util.encoders.Hex;
import ru.mipt.cybersecurity.util.test.SimpleTest;

public class ECElGamalTest
    extends SimpleTest
{
    public String getName()
    {
        return "ECElGamal";
    }

    public void performTest()
        throws Exception
    {
        BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
                curve,
                curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
                n);

        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
                    curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
                    params);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
            params);

        ParametersWithRandom pRandom = new ParametersWithRandom(pubKey, new SecureRandom());

        doTest(priKey, pRandom, BigInteger.valueOf(20));

        BigInteger rand = new BigInteger(pubKey.getParameters().getN().bitLength() - 1, new SecureRandom());

        doTest(priKey, pRandom, rand);
    }

    private void doTest(ECPrivateKeyParameters priKey, ParametersWithRandom pRandom, BigInteger value)
    {
        ECPoint data = priKey.getParameters().getG().multiply(value);

        ECEncryptor encryptor = new ECElGamalEncryptor();

        encryptor.init(pRandom);

        ECPair pair = encryptor.encrypt(data);

        ECDecryptor decryptor = new ECElGamalDecryptor();

        decryptor.init(priKey);

        ECPoint result = decryptor.decrypt(pair);

        if (!data.equals(result))
        {
            fail("point pair failed to decrypt back to original");
        }
    }

    public static void main(String[] args)
    {
        runTest(new ECElGamalTest());
    }
}
