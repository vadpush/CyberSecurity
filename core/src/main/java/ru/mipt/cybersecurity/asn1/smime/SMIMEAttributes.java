package ru.mipt.cybersecurity.asn1.smime;

import ru.mipt.cybersecurity.asn1.ASN1ObjectIdentifier;
import ru.mipt.cybersecurity.asn1.pkcs.PKCSObjectIdentifiers;

public interface SMIMEAttributes
{
    public static final ASN1ObjectIdentifier  smimeCapabilities = PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities;
    public static final ASN1ObjectIdentifier  encrypKeyPref = PKCSObjectIdentifiers.id_aa_encrypKeyPref;
}
