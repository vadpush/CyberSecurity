package ru.mipt.cybersecurity.asn1.test;

import ru.mipt.cybersecurity.asn1.ASN1ObjectIdentifier;
import ru.mipt.cybersecurity.asn1.DERSequence;
import ru.mipt.cybersecurity.asn1.cmc.BodyPartID;
import ru.mipt.cybersecurity.asn1.cmc.DecryptedPOP;
import ru.mipt.cybersecurity.asn1.x509.AlgorithmIdentifier;
import ru.mipt.cybersecurity.util.Arrays;
import ru.mipt.cybersecurity.util.test.SimpleTest;

public class DecryptedPOPTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new DecryptedPOPTest());
    }

    public String getName()
    {
        return "DecryptedPOPTest";
    }

    public void performTest()
        throws Exception
    {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.9.8.7.6")); // Not real!
        DecryptedPOP pop = new DecryptedPOP(new BodyPartID(10L), algId, "cats".getBytes());
        byte[] b = pop.getEncoded();
        DecryptedPOP popResult = DecryptedPOP.getInstance(b);
        isEquals("Bodypart id", popResult.getBodyPartID(), pop.getBodyPartID());
        isTrue("The POP", Arrays.areEqual(popResult.getThePOP(), pop.getThePOP()));
        isEquals("POP Result", popResult.getThePOPAlgID(), pop.getThePOPAlgID());

        try
        {
            DecryptedPOP.getInstance(new DERSequence(new BodyPartID(10L)));
            fail("Sequence must be 3 elements long");
        }
        catch (Throwable t)
        {
            isEquals(t.getClass(), IllegalArgumentException.class);
        }
    }
}
