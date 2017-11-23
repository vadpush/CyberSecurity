package ru.mipt.cybersecurity.crypto.tls;

import java.io.ByteArrayOutputStream;

import ru.mipt.cybersecurity.crypto.Digest;

class DigestInputBuffer extends ByteArrayOutputStream
{
    void updateDigest(Digest d)
    {
        d.update(this.buf, 0, count);
    }
}
