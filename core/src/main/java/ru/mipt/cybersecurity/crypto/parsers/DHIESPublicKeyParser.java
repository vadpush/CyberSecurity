package ru.mipt.cybersecurity.crypto.parsers;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import ru.mipt.cybersecurity.crypto.KeyParser;
import ru.mipt.cybersecurity.crypto.params.AsymmetricKeyParameter;
import ru.mipt.cybersecurity.crypto.params.DHParameters;
import ru.mipt.cybersecurity.crypto.params.DHPublicKeyParameters;
import ru.mipt.cybersecurity.util.io.Streams;

public class DHIESPublicKeyParser
    implements KeyParser
{
    private DHParameters dhParams;

    public DHIESPublicKeyParser(DHParameters dhParams)
    {
        this.dhParams = dhParams;
    }

    public AsymmetricKeyParameter readKey(InputStream stream)
        throws IOException
    {
        byte[] V = new byte[(dhParams.getP().bitLength() + 7) / 8];

        Streams.readFully(stream, V, 0, V.length);

        return new DHPublicKeyParameters(new BigInteger(1, V), dhParams);
    }
}
