package ru.mipt.cybersecurity.crypto;

import java.io.IOException;
import java.io.InputStream;

import ru.mipt.cybersecurity.crypto.params.AsymmetricKeyParameter;

public interface KeyParser
{
    AsymmetricKeyParameter readKey(InputStream stream)
        throws IOException;
}
