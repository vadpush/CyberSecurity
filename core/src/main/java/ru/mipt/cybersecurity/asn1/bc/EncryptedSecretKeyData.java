package ru.mipt.cybersecurity.asn1.bc;

import ru.mipt.cybersecurity.asn1.ASN1EncodableVector;
import ru.mipt.cybersecurity.asn1.ASN1Object;
import ru.mipt.cybersecurity.asn1.ASN1OctetString;
import ru.mipt.cybersecurity.asn1.ASN1Primitive;
import ru.mipt.cybersecurity.asn1.ASN1Sequence;
import ru.mipt.cybersecurity.asn1.DEROctetString;
import ru.mipt.cybersecurity.asn1.DERSequence;
import ru.mipt.cybersecurity.asn1.x509.AlgorithmIdentifier;
import ru.mipt.cybersecurity.util.Arrays;

/**
 * <pre>
 *     EncryptedSecretKeyData ::= SEQUENCE {
 *         keyEncryptionAlgorithm AlgorithmIdentifier,
 *         encryptedKeyData OCTET STRING
 *     }
 * </pre>
 */
public class EncryptedSecretKeyData
    extends ASN1Object
{
    private final AlgorithmIdentifier keyEncryptionAlgorithm;
    private final ASN1OctetString encryptedKeyData;

    public EncryptedSecretKeyData(AlgorithmIdentifier keyEncryptionAlgorithm, byte[] encryptedKeyData)
    {
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.encryptedKeyData = new DEROctetString(Arrays.clone(encryptedKeyData));
    }

    private EncryptedSecretKeyData(ASN1Sequence seq)
    {
        this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.encryptedKeyData = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public static EncryptedSecretKeyData getInstance(Object o)
    {
        if (o instanceof EncryptedSecretKeyData)
        {
            return (EncryptedSecretKeyData)o;
        }
        else if (o != null)
        {
            return new EncryptedSecretKeyData(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    public AlgorithmIdentifier getKeyEncryptionAlgorithm()
    {
        return keyEncryptionAlgorithm;
    }

    public byte[] getEncryptedKeyData()
    {
        return Arrays.clone(encryptedKeyData.getOctets());
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(keyEncryptionAlgorithm);
        v.add(encryptedKeyData);

        return new DERSequence(v);
    }
}
