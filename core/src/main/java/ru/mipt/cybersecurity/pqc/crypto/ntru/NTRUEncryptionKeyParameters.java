package ru.mipt.cybersecurity.pqc.crypto.ntru;

import ru.mipt.cybersecurity.crypto.params.AsymmetricKeyParameter;

public class NTRUEncryptionKeyParameters
    extends AsymmetricKeyParameter
{
    final protected NTRUEncryptionParameters params;

    public NTRUEncryptionKeyParameters(boolean privateKey, NTRUEncryptionParameters params)
    {
        super(privateKey);
        this.params = params;
    }

    public NTRUEncryptionParameters getParameters()
    {
        return params;
    }
}
