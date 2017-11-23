package ru.mipt.cybersecurity.crypto.tls;

import ru.mipt.cybersecurity.crypto.DSA;
import ru.mipt.cybersecurity.crypto.params.AsymmetricKeyParameter;
import ru.mipt.cybersecurity.crypto.params.ECPublicKeyParameters;
import ru.mipt.cybersecurity.crypto.signers.ECDSASigner;
import ru.mipt.cybersecurity.crypto.signers.HMacDSAKCalculator;

public class TlsECDSASigner
    extends TlsDSASigner
{
    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey)
    {
        return publicKey instanceof ECPublicKeyParameters;
    }

    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new ECDSASigner(new HMacDSAKCalculator(TlsUtils.createHash(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.ecdsa;
    }
}
