package ru.mipt.cybersecurity.crypto.agreement.kdf;

import java.io.IOException;

import ru.mipt.cybersecurity.asn1.ASN1EncodableVector;
import ru.mipt.cybersecurity.asn1.ASN1Encoding;
import ru.mipt.cybersecurity.asn1.ASN1ObjectIdentifier;
import ru.mipt.cybersecurity.asn1.DERNull;
import ru.mipt.cybersecurity.asn1.DEROctetString;
import ru.mipt.cybersecurity.asn1.DERSequence;
import ru.mipt.cybersecurity.asn1.DERTaggedObject;
import ru.mipt.cybersecurity.asn1.x509.AlgorithmIdentifier;
import ru.mipt.cybersecurity.crypto.DataLengthException;
import ru.mipt.cybersecurity.crypto.DerivationParameters;
import ru.mipt.cybersecurity.crypto.Digest;
import ru.mipt.cybersecurity.crypto.DigestDerivationFunction;
import ru.mipt.cybersecurity.crypto.generators.KDF2BytesGenerator;
import ru.mipt.cybersecurity.crypto.params.KDFParameters;
import ru.mipt.cybersecurity.util.Pack;

/**
 * X9.63 based key derivation function for ECDH CMS.
 */
public class ECDHKEKGenerator
    implements DigestDerivationFunction
{
    private DigestDerivationFunction kdf;

    private ASN1ObjectIdentifier algorithm;
    private int                 keySize;
    private byte[]              z;

    public ECDHKEKGenerator(
        Digest digest)
    {
        this.kdf = new KDF2BytesGenerator(digest);
    }

    public void init(DerivationParameters param)
    {
        DHKDFParameters params = (DHKDFParameters)param;

        this.algorithm = params.getAlgorithm();
        this.keySize = params.getKeySize();
        this.z = params.getZ();
    }

    public Digest getDigest()
    {
        return kdf.getDigest();
    }

    public int generateBytes(byte[] out, int outOff, int len)
        throws DataLengthException, IllegalArgumentException
    {
        // TODO Create an ASN.1 class for this (RFC3278)
        // ECC-CMS-SharedInfo
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new AlgorithmIdentifier(algorithm, DERNull.INSTANCE));
        v.add(new DERTaggedObject(true, 2, new DEROctetString(Pack.intToBigEndian(keySize))));

        try
        {
            kdf.init(new KDFParameters(z, new DERSequence(v).getEncoded(ASN1Encoding.DER)));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("unable to initialise kdf: " + e.getMessage());
        }

        return kdf.generateBytes(out, outOff, len);
    }
}
