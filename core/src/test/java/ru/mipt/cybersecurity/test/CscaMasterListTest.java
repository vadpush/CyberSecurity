package ru.mipt.cybersecurity.asn1.test;

import java.io.IOException;

import ru.mipt.cybersecurity.asn1.ASN1Primitive;
import ru.mipt.cybersecurity.asn1.icao.CscaMasterList;
import ru.mipt.cybersecurity.util.Arrays;
import ru.mipt.cybersecurity.util.io.Streams;
import ru.mipt.cybersecurity.util.test.SimpleTest;

public class CscaMasterListTest
    extends SimpleTest
{
    public String getName()
    {
        return "CscaMasterList";
    }

    public void performTest()
        throws Exception
    {
        byte[] input = getInput("masterlist-content.data");
        CscaMasterList parsedList
            = CscaMasterList.getInstance(ASN1Primitive.fromByteArray(input));

        if (parsedList.getCertStructs().length != 3)
        {
            fail("Cert structure parsing failed: incorrect length");
        }

        byte[] output = parsedList.getEncoded();
        if (!Arrays.areEqual(input, output))
        {
            fail("Encoding failed after parse");
        }
    }

    private byte[] getInput(String name)
        throws IOException
    {
        return Streams.readAll(getClass().getResourceAsStream(name));
    }

    public static void main(
        String[] args)
    {
        runTest(new CscaMasterListTest());
    }
}
