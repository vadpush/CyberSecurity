package ru.mipt.cybersecurity.asn1.test;


import ru.mipt.cybersecurity.asn1.ASN1Encodable;
import ru.mipt.cybersecurity.asn1.ASN1Integer;
import ru.mipt.cybersecurity.asn1.DERSequence;
import ru.mipt.cybersecurity.asn1.cmc.IdentityProofV2;
import ru.mipt.cybersecurity.asn1.pkcs.PKCSObjectIdentifiers;
import ru.mipt.cybersecurity.asn1.x509.AlgorithmIdentifier;
import ru.mipt.cybersecurity.util.test.SimpleTest;

public class IdentityProofV2Test
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new IdentityProofV2Test());
    }

    public String getName()
    {
        return "IdentityProofV2";
    }

    public void performTest()
        throws Exception
    {
        IdentityProofV2 proofV2 = new IdentityProofV2(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.encryptionAlgorithm, new ASN1Integer(10L)),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.bagtypes, new ASN1Integer(10L)),
            "Cats".getBytes()
        );

        byte[] b = proofV2.getEncoded();
        IdentityProofV2 proofV2Res = IdentityProofV2.getInstance(b);

        isEquals("proofAldID", proofV2.getProofAlgID(), proofV2Res.getProofAlgID());
        isEquals("macAlgId", proofV2.getMacAlgId(), proofV2Res.getMacAlgId());
        isTrue("witness",  areEqual(proofV2.getWitness(), proofV2Res.getWitness()));


        try
        {
            IdentityProofV2.getInstance(new DERSequence(new ASN1Encodable[0]));
            fail("Sequence must be length of 3");
        }
        catch (Throwable t)
        {
            isEquals("Exception incorrect", t.getClass(), IllegalArgumentException.class);
        }
    }
}
