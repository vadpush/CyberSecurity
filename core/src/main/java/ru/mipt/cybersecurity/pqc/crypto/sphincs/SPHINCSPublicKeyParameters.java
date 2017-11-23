package ru.mipt.cybersecurity.pqc.crypto.sphincs;

import ru.mipt.cybersecurity.crypto.params.AsymmetricKeyParameter;
import ru.mipt.cybersecurity.util.Arrays;

public class SPHINCSPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final byte[] keyData;

    public SPHINCSPublicKeyParameters(byte[] keyData)
    {
        super(false);
        this.keyData = Arrays.clone(keyData);
    }

    public byte[] getKeyData()
    {
        return Arrays.clone(keyData);
    }
}
