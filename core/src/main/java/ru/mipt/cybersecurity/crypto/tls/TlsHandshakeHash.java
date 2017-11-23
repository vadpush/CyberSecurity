package ru.mipt.cybersecurity.crypto.tls;

import ru.mipt.cybersecurity.crypto.Digest;

public interface TlsHandshakeHash
    extends Digest
{
    void init(TlsContext context);

    TlsHandshakeHash notifyPRFDetermined();

    void trackHashAlgorithm(short hashAlgorithm);

    void sealHashAlgorithms();

    TlsHandshakeHash stopTracking();

    Digest forkPRFHash();

    byte[] getFinalHash(short hashAlgorithm);
}
