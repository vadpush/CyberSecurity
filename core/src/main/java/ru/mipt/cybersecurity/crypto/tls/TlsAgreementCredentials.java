package ru.mipt.cybersecurity.crypto.tls;

import java.io.IOException;

import ru.mipt.cybersecurity.crypto.params.AsymmetricKeyParameter;

public interface TlsAgreementCredentials
    extends TlsCredentials
{
    byte[] generateAgreement(AsymmetricKeyParameter peerPublicKey)
        throws IOException;
}
