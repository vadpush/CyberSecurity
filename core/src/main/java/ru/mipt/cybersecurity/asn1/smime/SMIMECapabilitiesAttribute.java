package ru.mipt.cybersecurity.asn1.smime;

import ru.mipt.cybersecurity.asn1.DERSequence;
import ru.mipt.cybersecurity.asn1.DERSet;
import ru.mipt.cybersecurity.asn1.cms.Attribute;

public class SMIMECapabilitiesAttribute
    extends Attribute
{
    public SMIMECapabilitiesAttribute(
        SMIMECapabilityVector capabilities)
    {
        super(SMIMEAttributes.smimeCapabilities,
                new DERSet(new DERSequence(capabilities.toASN1EncodableVector())));
    }
}
