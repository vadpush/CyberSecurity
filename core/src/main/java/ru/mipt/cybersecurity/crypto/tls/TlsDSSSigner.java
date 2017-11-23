package ru.mipt.cybersecurity.crypto.tls;

import ru.mipt.cybersecurity.crypto.DSA;
import ru.mipt.cybersecurity.crypto.params.AsymmetricKeyParameter;
import ru.mipt.cybersecurity.crypto.params.DSAPublicKeyParameters;
import ru.mipt.cybersecurity.crypto.signers.DSASigner;
import ru.mipt.cybersecurity.crypto.signers.HMacDSAKCalculator;

public class TlsDSSSigner
    extends TlsDSASigner
{
    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey)
    {
        return publicKey instanceof DSAPublicKeyParameters;
    }

    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new DSASigner(new HMacDSAKCalculator(TlsUtils.createHash(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.dsa;
    }
}
