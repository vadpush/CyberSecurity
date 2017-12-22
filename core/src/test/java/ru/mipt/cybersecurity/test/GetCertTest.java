package ru.mipt.cybersecurity.asn1.test;

import java.math.BigInteger;

import ru.mipt.cybersecurity.asn1.ASN1Integer;
import ru.mipt.cybersecurity.asn1.DERSequence;
import ru.mipt.cybersecurity.asn1.cmc.GetCert;
import ru.mipt.cybersecurity.asn1.x509.GeneralName;
import ru.mipt.cybersecurity.util.test.SimpleTest;


public class GetCertTest extends SimpleTest
{
    public static void main(String[] args) {
        runTest(new GetCertTest());
    }

    public String getName()
    {
        return "GetCertTest";
    }

    public void performTest()
        throws Exception
    {
        GetCert gs = new GetCert(new GeneralName(GeneralName.dNSName,"fish"),new BigInteger("109"));
        byte[] b = gs.getEncoded();
        GetCert gsResp = GetCert.getInstance(b);

        isEquals("Issuer Name",gs.getIssuerName(), gsResp.getIssuerName());
        isEquals("Serial Number",gs.getSerialNumber(), gsResp.getSerialNumber());

        try {
            GetCert.getInstance(new DERSequence(new ASN1Integer(1L)));
            fail("Sequence must be length of 2");
        } catch (Throwable t) {
            isEquals("Wrong exception",t.getClass(), IllegalArgumentException.class);
        }

    }
}
