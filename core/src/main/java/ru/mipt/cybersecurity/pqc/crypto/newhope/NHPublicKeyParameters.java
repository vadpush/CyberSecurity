package ru.mipt.cybersecurity.pqc.crypto.newhope;

import ru.mipt.cybersecurity.crypto.params.AsymmetricKeyParameter;
import ru.mipt.cybersecurity.util.Arrays;

public class NHPublicKeyParameters
    extends AsymmetricKeyParameter
{
    final byte[] pubData;

    public NHPublicKeyParameters(byte[] pubData)
    {
        super(false);
        this.pubData = Arrays.clone(pubData);
    }

    /**
     * Return the public key data.
     *
     * @return the public key values.
     */
    public byte[] getPubData()
    {
        return Arrays.clone(pubData);
    }
}
