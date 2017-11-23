package ru.mipt.cybersecurity.crypto.tls;

import java.math.BigInteger;

import ru.mipt.cybersecurity.crypto.BasicAgreement;
import ru.mipt.cybersecurity.crypto.agreement.DHBasicAgreement;
import ru.mipt.cybersecurity.crypto.agreement.ECDHBasicAgreement;
import ru.mipt.cybersecurity.crypto.params.AsymmetricKeyParameter;
import ru.mipt.cybersecurity.crypto.params.DHPrivateKeyParameters;
import ru.mipt.cybersecurity.crypto.params.ECPrivateKeyParameters;
import ru.mipt.cybersecurity.util.BigIntegers;

public class DefaultTlsAgreementCredentials
    extends AbstractTlsAgreementCredentials
{
    protected Certificate certificate;
    protected AsymmetricKeyParameter privateKey;

    protected BasicAgreement basicAgreement;
    protected boolean truncateAgreement;

    public DefaultTlsAgreementCredentials(Certificate certificate, AsymmetricKeyParameter privateKey)
    {
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty())
        {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }
        if (privateKey == null)
        {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }
        if (!privateKey.isPrivate())
        {
            throw new IllegalArgumentException("'privateKey' must be private");
        }

        if (privateKey instanceof DHPrivateKeyParameters)
        {
            basicAgreement = new DHBasicAgreement();
            truncateAgreement = true;
        }
        else if (privateKey instanceof ECPrivateKeyParameters)
        {
            basicAgreement = new ECDHBasicAgreement();
            truncateAgreement = false;
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: "
                + privateKey.getClass().getName());
        }

        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public byte[] generateAgreement(AsymmetricKeyParameter peerPublicKey)
    {
        basicAgreement.init(privateKey);
        BigInteger agreementValue = basicAgreement.calculateAgreement(peerPublicKey);

        if (truncateAgreement)
        {
            return BigIntegers.asUnsignedByteArray(agreementValue);
        }

        return BigIntegers.asUnsignedByteArray(basicAgreement.getFieldSize(), agreementValue);
    }
}
