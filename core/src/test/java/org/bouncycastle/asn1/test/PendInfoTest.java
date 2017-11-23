package ru.mipt.cybersecurity.asn1.test;

import java.util.Date;

import ru.mipt.cybersecurity.asn1.ASN1GeneralizedTime;
import ru.mipt.cybersecurity.asn1.DERSequence;
import ru.mipt.cybersecurity.asn1.cmc.PendInfo;
import ru.mipt.cybersecurity.util.test.SimpleTest;


public class PendInfoTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new PendInfoTest());
    }

    public String getName()
    {
        return "PendInfoTest";
    }

    public void performTest()
        throws Exception
    {
        PendInfo info = new PendInfo("".getBytes(), new ASN1GeneralizedTime(new Date()));
        byte[] b = info.getEncoded();
        PendInfo infoResult = PendInfo.getInstance(b);

        isTrue("pendToken", areEqual(info.getPendToken(), infoResult.getPendToken()));
        isEquals("pendTime", info.getPendTime(), infoResult.getPendTime());

        try
        {
            PendInfo.getInstance(new DERSequence());
            fail("Sequence length not 2");
        }
        catch (Throwable t)
        {
            isEquals("Exception type", t.getClass(), IllegalArgumentException.class);
        }

    }
}
