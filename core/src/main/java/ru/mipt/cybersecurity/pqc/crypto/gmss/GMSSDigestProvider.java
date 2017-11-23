package ru.mipt.cybersecurity.pqc.crypto.gmss;

import ru.mipt.cybersecurity.crypto.Digest;

public interface GMSSDigestProvider
{
    Digest get();
}
