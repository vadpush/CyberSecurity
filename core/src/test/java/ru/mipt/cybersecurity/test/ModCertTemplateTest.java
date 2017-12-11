package ru.mipt.cybersecurity.asn1.test;

import ru.mipt.cybersecurity.asn1.ASN1Encodable;
import ru.mipt.cybersecurity.asn1.ASN1Integer;
import ru.mipt.cybersecurity.asn1.DERSequence;
import ru.mipt.cybersecurity.asn1.DERTaggedObject;
import ru.mipt.cybersecurity.asn1.DLSequence;
import ru.mipt.cybersecurity.asn1.cmc.BodyPartID;
import ru.mipt.cybersecurity.asn1.cmc.BodyPartList;
import ru.mipt.cybersecurity.asn1.cmc.BodyPartPath;
import ru.mipt.cybersecurity.asn1.cmc.ModCertTemplate;
import ru.mipt.cybersecurity.asn1.crmf.CertTemplate;
import ru.mipt.cybersecurity.util.test.SimpleTest;


public class ModCertTemplateTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new ModCertTemplateTest());
    }

    public String getName()
    {
        return "ModCertTemplateTest";
    }

    public void performTest()
        throws Exception
    {

        BodyPartPath pkiDataReference = new BodyPartPath(new BodyPartID(10L));
        BodyPartList certReferences = new BodyPartList(new BodyPartID(12L));
        boolean replace = false;
        CertTemplate certTemplate = CertTemplate.getInstance(new DLSequence(new DERTaggedObject(false, 1, new ASN1Integer(34L))));
        {
            ModCertTemplate modCertTemplate = new ModCertTemplate(
                pkiDataReference,
                certReferences,
                replace,
                certTemplate
            );

            byte[] b = modCertTemplate.getEncoded();

            ModCertTemplate modCertTemplateResult = ModCertTemplate.getInstance(b);

            isEquals("pkiDataReference", modCertTemplate.getPkiDataReference(), modCertTemplateResult.getPkiDataReference());
            isEquals("certReference", modCertTemplate.getCertReferences(), modCertTemplateResult.getCertReferences());
            isEquals("replacingFields", modCertTemplate.isReplacingFields(), modCertTemplateResult.isReplacingFields());
            isEquals("certTemplate", modCertTemplate.getCertTemplate().getSerialNumber(), modCertTemplateResult.getCertTemplate().getSerialNumber());
        }


        {
            // Test default 'result'
            ModCertTemplate mct = ModCertTemplate.getInstance(new DERSequence(new ASN1Encodable[]{
                pkiDataReference,
                certReferences,
                certTemplate
            }));

            isEquals("pkiDataReference", mct.getPkiDataReference(), pkiDataReference);
            isEquals("certReference", mct.getCertReferences(), certReferences);
            isEquals("DEFAULT TRUE on replacingFields", mct.isReplacingFields(), true);
            isEquals("certTemplate", mct.getCertTemplate().getSerialNumber(), certTemplate.getSerialNumber());
        }


        try
        {
            ModCertTemplate.getInstance(new DERSequence());
            fail("Sequence must be 3 or 4.");
        }
        catch (Throwable t)
        {
            isEquals(t.getClass(), IllegalArgumentException.class);
        }


    }
}
