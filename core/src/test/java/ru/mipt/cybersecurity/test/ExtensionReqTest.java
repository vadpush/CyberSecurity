package ru.mipt.cybersecurity.asn1.test;

import ru.mipt.cybersecurity.asn1.ASN1Boolean;
import ru.mipt.cybersecurity.asn1.ASN1ObjectIdentifier;
import ru.mipt.cybersecurity.asn1.DEROctetString;
import ru.mipt.cybersecurity.asn1.cmc.ExtensionReq;
import ru.mipt.cybersecurity.asn1.x509.Extension;
import ru.mipt.cybersecurity.util.test.SimpleTest;


public class ExtensionReqTest
    extends SimpleTest
{
    public String getName()
    {
        return "ExtensionReqTest";
    }

    public void performTest()
        throws Exception
    {
        ExtensionReq extensionReq = new ExtensionReq(
            new Extension(
                new ASN1ObjectIdentifier("1.2.4"), ASN1Boolean.FALSE, new DEROctetString("abcdef".getBytes())
            ));
        byte[] b = extensionReq.getEncoded();

        ExtensionReq extensionReqResult = ExtensionReq.getInstance(b);

        isEquals("Extensions", extensionReq.getExtensions()[0], extensionReqResult.getExtensions()[0]);

    }

    public static void main(String[] args)
    {
        runTest(new ExtensionReqTest());
    }

}
