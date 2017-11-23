package ru.mipt.cybersecurity.crypto.tls;

import java.io.ByteArrayOutputStream;

import ru.mipt.cybersecurity.crypto.Signer;

class SignerInputBuffer extends ByteArrayOutputStream
{
    void updateSigner(Signer s)
    {
        s.update(this.buf, 0, count);
    }
}