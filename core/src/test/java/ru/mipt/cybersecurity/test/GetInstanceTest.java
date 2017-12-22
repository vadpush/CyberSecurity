package ru.mipt.cybersecurity.asn1.test;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.Date;
import java.util.Vector;

import junit.framework.TestCase;
import ru.mipt.cybersecurity.asn1.ASN1EncodableVector;
import ru.mipt.cybersecurity.asn1.ASN1Enumerated;
import ru.mipt.cybersecurity.asn1.ASN1GeneralizedTime;
import ru.mipt.cybersecurity.asn1.ASN1Integer;
import ru.mipt.cybersecurity.asn1.ASN1Object;
import ru.mipt.cybersecurity.asn1.ASN1ObjectIdentifier;
import ru.mipt.cybersecurity.asn1.ASN1TaggedObject;
import ru.mipt.cybersecurity.asn1.ASN1UTCTime;
import ru.mipt.cybersecurity.asn1.DERBMPString;
import ru.mipt.cybersecurity.asn1.DERBitString;
import ru.mipt.cybersecurity.asn1.DERGeneralString;
import ru.mipt.cybersecurity.asn1.DERIA5String;
import ru.mipt.cybersecurity.asn1.DERNull;
import ru.mipt.cybersecurity.asn1.DERNumericString;
import ru.mipt.cybersecurity.asn1.DEROctetString;
import ru.mipt.cybersecurity.asn1.DERPrintableString;
import ru.mipt.cybersecurity.asn1.DERSequence;
import ru.mipt.cybersecurity.asn1.DERSet;
import ru.mipt.cybersecurity.asn1.DERT61String;
import ru.mipt.cybersecurity.asn1.DERTaggedObject;
import ru.mipt.cybersecurity.asn1.DERUTF8String;
import ru.mipt.cybersecurity.asn1.DERUniversalString;
import ru.mipt.cybersecurity.asn1.DERVisibleString;
import ru.mipt.cybersecurity.asn1.cmp.CAKeyUpdAnnContent;
import ru.mipt.cybersecurity.asn1.cmp.CMPCertificate;
import ru.mipt.cybersecurity.asn1.cmp.CRLAnnContent;
import ru.mipt.cybersecurity.asn1.cmp.CertConfirmContent;
import ru.mipt.cybersecurity.asn1.cmp.CertOrEncCert;
import ru.mipt.cybersecurity.asn1.cmp.CertRepMessage;
import ru.mipt.cybersecurity.asn1.cmp.CertResponse;
import ru.mipt.cybersecurity.asn1.cmp.CertifiedKeyPair;
import ru.mipt.cybersecurity.asn1.cmp.Challenge;
import ru.mipt.cybersecurity.asn1.cmp.ErrorMsgContent;
import ru.mipt.cybersecurity.asn1.cmp.GenMsgContent;
import ru.mipt.cybersecurity.asn1.cmp.GenRepContent;
import ru.mipt.cybersecurity.asn1.cmp.InfoTypeAndValue;
import ru.mipt.cybersecurity.asn1.cmp.KeyRecRepContent;
import ru.mipt.cybersecurity.asn1.cmp.OOBCertHash;
import ru.mipt.cybersecurity.asn1.cmp.PBMParameter;
import ru.mipt.cybersecurity.asn1.cmp.PKIBody;
import ru.mipt.cybersecurity.asn1.cmp.PKIConfirmContent;
import ru.mipt.cybersecurity.asn1.cmp.PKIFailureInfo;
import ru.mipt.cybersecurity.asn1.cmp.PKIFreeText;
import ru.mipt.cybersecurity.asn1.cmp.PKIHeader;
import ru.mipt.cybersecurity.asn1.cmp.PKIMessage;
import ru.mipt.cybersecurity.asn1.cmp.PKIMessages;
import ru.mipt.cybersecurity.asn1.cmp.PKIStatus;
import ru.mipt.cybersecurity.asn1.cmp.PKIStatusInfo;
import ru.mipt.cybersecurity.asn1.cmp.POPODecKeyChallContent;
import ru.mipt.cybersecurity.asn1.cmp.POPODecKeyRespContent;
import ru.mipt.cybersecurity.asn1.cmp.PollRepContent;
import ru.mipt.cybersecurity.asn1.cmp.PollReqContent;
import ru.mipt.cybersecurity.asn1.cmp.ProtectedPart;
import ru.mipt.cybersecurity.asn1.cmp.RevAnnContent;
import ru.mipt.cybersecurity.asn1.cmp.RevDetails;
import ru.mipt.cybersecurity.asn1.cmp.RevRepContent;
import ru.mipt.cybersecurity.asn1.cmp.RevReqContent;
import ru.mipt.cybersecurity.asn1.cms.Attribute;
import ru.mipt.cybersecurity.asn1.cms.Attributes;
import ru.mipt.cybersecurity.asn1.cms.AuthEnvelopedData;
import ru.mipt.cybersecurity.asn1.cms.AuthenticatedData;
import ru.mipt.cybersecurity.asn1.cms.CompressedData;
import ru.mipt.cybersecurity.asn1.cms.ContentInfo;
import ru.mipt.cybersecurity.asn1.cms.EncryptedContentInfo;
import ru.mipt.cybersecurity.asn1.cms.EncryptedData;
import ru.mipt.cybersecurity.asn1.cms.EnvelopedData;
import ru.mipt.cybersecurity.asn1.cms.Evidence;
import ru.mipt.cybersecurity.asn1.cms.IssuerAndSerialNumber;
import ru.mipt.cybersecurity.asn1.cms.KEKIdentifier;
import ru.mipt.cybersecurity.asn1.cms.KEKRecipientInfo;
import ru.mipt.cybersecurity.asn1.cms.KeyAgreeRecipientIdentifier;
import ru.mipt.cybersecurity.asn1.cms.KeyAgreeRecipientInfo;
import ru.mipt.cybersecurity.asn1.cms.KeyTransRecipientInfo;
import ru.mipt.cybersecurity.asn1.cms.MetaData;
import ru.mipt.cybersecurity.asn1.cms.OriginatorIdentifierOrKey;
import ru.mipt.cybersecurity.asn1.cms.OriginatorInfo;
import ru.mipt.cybersecurity.asn1.cms.OriginatorPublicKey;
import ru.mipt.cybersecurity.asn1.cms.OtherKeyAttribute;
import ru.mipt.cybersecurity.asn1.cms.OtherRecipientInfo;
import ru.mipt.cybersecurity.asn1.cms.PasswordRecipientInfo;
import ru.mipt.cybersecurity.asn1.cms.RecipientEncryptedKey;
import ru.mipt.cybersecurity.asn1.cms.RecipientIdentifier;
import ru.mipt.cybersecurity.asn1.cms.RecipientInfo;
import ru.mipt.cybersecurity.asn1.cms.RecipientKeyIdentifier;
import ru.mipt.cybersecurity.asn1.cms.SignerIdentifier;
import ru.mipt.cybersecurity.asn1.cms.SignerInfo;
import ru.mipt.cybersecurity.asn1.cms.TimeStampAndCRL;
import ru.mipt.cybersecurity.asn1.cms.TimeStampTokenEvidence;
import ru.mipt.cybersecurity.asn1.cms.TimeStampedData;
import ru.mipt.cybersecurity.asn1.cms.ecc.MQVuserKeyingMaterial;
import ru.mipt.cybersecurity.asn1.crmf.AttributeTypeAndValue;
import ru.mipt.cybersecurity.asn1.crmf.CertId;
import ru.mipt.cybersecurity.asn1.crmf.CertReqMessages;
import ru.mipt.cybersecurity.asn1.crmf.CertReqMsg;
import ru.mipt.cybersecurity.asn1.crmf.CertRequest;
import ru.mipt.cybersecurity.asn1.crmf.CertTemplate;
import ru.mipt.cybersecurity.asn1.crmf.Controls;
import ru.mipt.cybersecurity.asn1.crmf.EncKeyWithID;
import ru.mipt.cybersecurity.asn1.crmf.EncryptedKey;
import ru.mipt.cybersecurity.asn1.crmf.EncryptedValue;
import ru.mipt.cybersecurity.asn1.crmf.OptionalValidity;
import ru.mipt.cybersecurity.asn1.crmf.PKIArchiveOptions;
import ru.mipt.cybersecurity.asn1.crmf.PKIPublicationInfo;
import ru.mipt.cybersecurity.asn1.crmf.PKMACValue;
import ru.mipt.cybersecurity.asn1.crmf.POPOPrivKey;
import ru.mipt.cybersecurity.asn1.crmf.POPOSigningKey;
import ru.mipt.cybersecurity.asn1.crmf.POPOSigningKeyInput;
import ru.mipt.cybersecurity.asn1.crmf.ProofOfPossession;
import ru.mipt.cybersecurity.asn1.crmf.SinglePubInfo;
import ru.mipt.cybersecurity.asn1.cryptopro.ECGOST3410ParamSetParameters;
import ru.mipt.cybersecurity.asn1.cryptopro.GOST28147Parameters;
import ru.mipt.cybersecurity.asn1.cryptopro.GOST3410ParamSetParameters;
import ru.mipt.cybersecurity.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import ru.mipt.cybersecurity.asn1.eac.CVCertificate;
import ru.mipt.cybersecurity.asn1.eac.CVCertificateRequest;
import ru.mipt.cybersecurity.asn1.eac.CertificateBody;
import ru.mipt.cybersecurity.asn1.eac.PublicKeyDataObject;
import ru.mipt.cybersecurity.asn1.eac.RSAPublicKey;
import ru.mipt.cybersecurity.asn1.eac.UnsignedInteger;
import ru.mipt.cybersecurity.asn1.esf.CommitmentTypeIndication;
import ru.mipt.cybersecurity.asn1.esf.CommitmentTypeQualifier;
import ru.mipt.cybersecurity.asn1.esf.CompleteRevocationRefs;
import ru.mipt.cybersecurity.asn1.esf.CrlIdentifier;
import ru.mipt.cybersecurity.asn1.esf.CrlListID;
import ru.mipt.cybersecurity.asn1.esf.CrlOcspRef;
import ru.mipt.cybersecurity.asn1.esf.CrlValidatedID;
import ru.mipt.cybersecurity.asn1.esf.OcspIdentifier;
import ru.mipt.cybersecurity.asn1.esf.OcspListID;
import ru.mipt.cybersecurity.asn1.esf.OcspResponsesID;
import ru.mipt.cybersecurity.asn1.esf.OtherHash;
import ru.mipt.cybersecurity.asn1.esf.OtherHashAlgAndValue;
import ru.mipt.cybersecurity.asn1.esf.OtherRevRefs;
import ru.mipt.cybersecurity.asn1.esf.OtherRevVals;
import ru.mipt.cybersecurity.asn1.esf.RevocationValues;
import ru.mipt.cybersecurity.asn1.esf.SPUserNotice;
import ru.mipt.cybersecurity.asn1.esf.SPuri;
import ru.mipt.cybersecurity.asn1.esf.SigPolicyQualifierInfo;
import ru.mipt.cybersecurity.asn1.esf.SigPolicyQualifiers;
import ru.mipt.cybersecurity.asn1.esf.SignaturePolicyId;
import ru.mipt.cybersecurity.asn1.esf.SignaturePolicyIdentifier;
import ru.mipt.cybersecurity.asn1.esf.SignerAttribute;
import ru.mipt.cybersecurity.asn1.esf.SignerLocation;
import ru.mipt.cybersecurity.asn1.ess.ContentHints;
import ru.mipt.cybersecurity.asn1.ess.ContentIdentifier;
import ru.mipt.cybersecurity.asn1.ess.ESSCertID;
import ru.mipt.cybersecurity.asn1.ess.ESSCertIDv2;
import ru.mipt.cybersecurity.asn1.ess.OtherCertID;
import ru.mipt.cybersecurity.asn1.ess.OtherSigningCertificate;
import ru.mipt.cybersecurity.asn1.ess.SigningCertificate;
import ru.mipt.cybersecurity.asn1.ess.SigningCertificateV2;
import ru.mipt.cybersecurity.asn1.icao.CscaMasterList;
import ru.mipt.cybersecurity.asn1.icao.DataGroupHash;
import ru.mipt.cybersecurity.asn1.icao.LDSSecurityObject;
import ru.mipt.cybersecurity.asn1.icao.LDSVersionInfo;
import ru.mipt.cybersecurity.asn1.isismtt.ocsp.CertHash;
import ru.mipt.cybersecurity.asn1.isismtt.ocsp.RequestedCertificate;
import ru.mipt.cybersecurity.asn1.isismtt.x509.AdditionalInformationSyntax;
import ru.mipt.cybersecurity.asn1.isismtt.x509.AdmissionSyntax;
import ru.mipt.cybersecurity.asn1.isismtt.x509.Admissions;
import ru.mipt.cybersecurity.asn1.isismtt.x509.DeclarationOfMajority;
import ru.mipt.cybersecurity.asn1.isismtt.x509.MonetaryLimit;
import ru.mipt.cybersecurity.asn1.isismtt.x509.NamingAuthority;
import ru.mipt.cybersecurity.asn1.isismtt.x509.ProcurationSyntax;
import ru.mipt.cybersecurity.asn1.isismtt.x509.ProfessionInfo;
import ru.mipt.cybersecurity.asn1.isismtt.x509.Restriction;
import ru.mipt.cybersecurity.asn1.misc.CAST5CBCParameters;
import ru.mipt.cybersecurity.asn1.misc.IDEACBCPar;
import ru.mipt.cybersecurity.asn1.mozilla.PublicKeyAndChallenge;
import ru.mipt.cybersecurity.asn1.ocsp.BasicOCSPResponse;
import ru.mipt.cybersecurity.asn1.ocsp.CertID;
import ru.mipt.cybersecurity.asn1.ocsp.CertStatus;
import ru.mipt.cybersecurity.asn1.ocsp.CrlID;
import ru.mipt.cybersecurity.asn1.ocsp.OCSPRequest;
import ru.mipt.cybersecurity.asn1.ocsp.OCSPResponse;
import ru.mipt.cybersecurity.asn1.ocsp.OCSPResponseStatus;
import ru.mipt.cybersecurity.asn1.ocsp.Request;
import ru.mipt.cybersecurity.asn1.ocsp.ResponderID;
import ru.mipt.cybersecurity.asn1.ocsp.ResponseBytes;
import ru.mipt.cybersecurity.asn1.ocsp.ResponseData;
import ru.mipt.cybersecurity.asn1.ocsp.RevokedInfo;
import ru.mipt.cybersecurity.asn1.ocsp.Signature;
import ru.mipt.cybersecurity.asn1.ocsp.SingleResponse;
import ru.mipt.cybersecurity.asn1.ocsp.TBSRequest;
import ru.mipt.cybersecurity.asn1.oiw.OIWObjectIdentifiers;
import ru.mipt.cybersecurity.asn1.pkcs.AuthenticatedSafe;
import ru.mipt.cybersecurity.asn1.pkcs.CertificationRequest;
import ru.mipt.cybersecurity.asn1.pkcs.CertificationRequestInfo;
import ru.mipt.cybersecurity.asn1.pkcs.DHParameter;
import ru.mipt.cybersecurity.asn1.pkcs.EncryptedPrivateKeyInfo;
import ru.mipt.cybersecurity.asn1.pkcs.MacData;
import ru.mipt.cybersecurity.asn1.pkcs.PBEParameter;
import ru.mipt.cybersecurity.asn1.pkcs.PBES2Parameters;
import ru.mipt.cybersecurity.asn1.pkcs.PBKDF2Params;
import ru.mipt.cybersecurity.asn1.pkcs.PKCS12PBEParams;
import ru.mipt.cybersecurity.asn1.pkcs.Pfx;
import ru.mipt.cybersecurity.asn1.pkcs.PrivateKeyInfo;
import ru.mipt.cybersecurity.asn1.pkcs.RC2CBCParameter;
import ru.mipt.cybersecurity.asn1.pkcs.RSAESOAEPparams;
import ru.mipt.cybersecurity.asn1.pkcs.RSAPrivateKey;
import ru.mipt.cybersecurity.asn1.pkcs.RSASSAPSSparams;
import ru.mipt.cybersecurity.asn1.pkcs.SafeBag;
import ru.mipt.cybersecurity.asn1.pkcs.SignedData;
import ru.mipt.cybersecurity.asn1.sec.ECPrivateKey;
import ru.mipt.cybersecurity.asn1.smime.SMIMECapabilities;
import ru.mipt.cybersecurity.asn1.smime.SMIMECapability;
import ru.mipt.cybersecurity.asn1.tsp.Accuracy;
import ru.mipt.cybersecurity.asn1.tsp.MessageImprint;
import ru.mipt.cybersecurity.asn1.tsp.TSTInfo;
import ru.mipt.cybersecurity.asn1.tsp.TimeStampReq;
import ru.mipt.cybersecurity.asn1.tsp.TimeStampResp;
import ru.mipt.cybersecurity.asn1.x500.DirectoryString;
import ru.mipt.cybersecurity.asn1.x500.RDN;
import ru.mipt.cybersecurity.asn1.x500.X500Name;
import ru.mipt.cybersecurity.asn1.x509.AccessDescription;
import ru.mipt.cybersecurity.asn1.x509.AlgorithmIdentifier;
import ru.mipt.cybersecurity.asn1.x509.AttCertIssuer;
import ru.mipt.cybersecurity.asn1.x509.AttCertValidityPeriod;
import ru.mipt.cybersecurity.asn1.x509.AttributeCertificate;
import ru.mipt.cybersecurity.asn1.x509.AttributeCertificateInfo;
import ru.mipt.cybersecurity.asn1.x509.AuthorityInformationAccess;
import ru.mipt.cybersecurity.asn1.x509.AuthorityKeyIdentifier;
import ru.mipt.cybersecurity.asn1.x509.BasicConstraints;
import ru.mipt.cybersecurity.asn1.x509.CRLDistPoint;
import ru.mipt.cybersecurity.asn1.x509.CRLNumber;
import ru.mipt.cybersecurity.asn1.x509.CRLReason;
import ru.mipt.cybersecurity.asn1.x509.Certificate;
import ru.mipt.cybersecurity.asn1.x509.CertificateList;
import ru.mipt.cybersecurity.asn1.x509.CertificatePair;
import ru.mipt.cybersecurity.asn1.x509.CertificatePolicies;
import ru.mipt.cybersecurity.asn1.x509.DSAParameter;
import ru.mipt.cybersecurity.asn1.x509.DigestInfo;
import ru.mipt.cybersecurity.asn1.x509.DisplayText;
import ru.mipt.cybersecurity.asn1.x509.DistributionPoint;
import ru.mipt.cybersecurity.asn1.x509.DistributionPointName;
import ru.mipt.cybersecurity.asn1.x509.ExtendedKeyUsage;
import ru.mipt.cybersecurity.asn1.x509.Extensions;
import ru.mipt.cybersecurity.asn1.x509.GeneralName;
import ru.mipt.cybersecurity.asn1.x509.GeneralNames;
import ru.mipt.cybersecurity.asn1.x509.GeneralSubtree;
import ru.mipt.cybersecurity.asn1.x509.Holder;
import ru.mipt.cybersecurity.asn1.x509.IetfAttrSyntax;
import ru.mipt.cybersecurity.asn1.x509.IssuerSerial;
import ru.mipt.cybersecurity.asn1.x509.IssuingDistributionPoint;
import ru.mipt.cybersecurity.asn1.x509.NameConstraints;
import ru.mipt.cybersecurity.asn1.x509.NoticeReference;
import ru.mipt.cybersecurity.asn1.x509.ObjectDigestInfo;
import ru.mipt.cybersecurity.asn1.x509.PolicyInformation;
import ru.mipt.cybersecurity.asn1.x509.PolicyMappings;
import ru.mipt.cybersecurity.asn1.x509.PolicyQualifierInfo;
import ru.mipt.cybersecurity.asn1.x509.PrivateKeyUsagePeriod;
import ru.mipt.cybersecurity.asn1.x509.RoleSyntax;
import ru.mipt.cybersecurity.asn1.x509.SubjectDirectoryAttributes;
import ru.mipt.cybersecurity.asn1.x509.SubjectKeyIdentifier;
import ru.mipt.cybersecurity.asn1.x509.SubjectPublicKeyInfo;
import ru.mipt.cybersecurity.asn1.x509.TBSCertList;
import ru.mipt.cybersecurity.asn1.x509.TBSCertificate;
import ru.mipt.cybersecurity.asn1.x509.TBSCertificateStructure;
import ru.mipt.cybersecurity.asn1.x509.Target;
import ru.mipt.cybersecurity.asn1.x509.TargetInformation;
import ru.mipt.cybersecurity.asn1.x509.Targets;
import ru.mipt.cybersecurity.asn1.x509.Time;
import ru.mipt.cybersecurity.asn1.x509.UserNotice;
import ru.mipt.cybersecurity.asn1.x509.V2Form;
import ru.mipt.cybersecurity.asn1.x509.X509CertificateStructure;
import ru.mipt.cybersecurity.asn1.x509.X509Extensions;
import ru.mipt.cybersecurity.asn1.x509.qualified.BiometricData;
import ru.mipt.cybersecurity.asn1.x509.qualified.Iso4217CurrencyCode;
import ru.mipt.cybersecurity.asn1.x509.qualified.MonetaryValue;
import ru.mipt.cybersecurity.asn1.x509.qualified.QCStatement;
import ru.mipt.cybersecurity.asn1.x509.qualified.SemanticsInformation;
import ru.mipt.cybersecurity.asn1.x509.qualified.TypeOfBiometricData;
import ru.mipt.cybersecurity.asn1.x509.sigi.NameOrPseudonym;
import ru.mipt.cybersecurity.asn1.x509.sigi.PersonalData;
import ru.mipt.cybersecurity.asn1.x9.DHDomainParameters;
import ru.mipt.cybersecurity.asn1.x9.DHPublicKey;
import ru.mipt.cybersecurity.asn1.x9.DHValidationParms;
import ru.mipt.cybersecurity.asn1.x9.X962Parameters;
import ru.mipt.cybersecurity.asn1.x9.X9ECParameters;
import ru.mipt.cybersecurity.util.Integers;
import ru.mipt.cybersecurity.util.encoders.Base64;

public class GetInstanceTest
    extends TestCase
{
    public static byte[]  attrCert = Base64.decode(
            "MIIHQDCCBqkCAQEwgZChgY2kgYowgYcxHDAaBgkqhkiG9w0BCQEWDW1sb3JjaEB2"
          + "dC5lZHUxHjAcBgNVBAMTFU1hcmt1cyBMb3JjaCAobWxvcmNoKTEbMBkGA1UECxMS"
          + "VmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAyMQswCQYDVQQKEwJ2"
          + "dDELMAkGA1UEBhMCVVMwgYmkgYYwgYMxGzAZBgkqhkiG9w0BCQEWDHNzaGFoQHZ0"
          + "LmVkdTEbMBkGA1UEAxMSU3VtaXQgU2hhaCAoc3NoYWgpMRswGQYDVQQLExJWaXJn"
          + "aW5pYSBUZWNoIFVzZXIxEDAOBgNVBAsTB0NsYXNzIDExCzAJBgNVBAoTAnZ0MQsw"
          + "CQYDVQQGEwJVUzANBgkqhkiG9w0BAQQFAAIBBTAiGA8yMDAzMDcxODE2MDgwMloY"
          + "DzIwMDMwNzI1MTYwODAyWjCCBU0wggVJBgorBgEEAbRoCAEBMYIFORaCBTU8UnVs"
          + "ZSBSdWxlSWQ9IkZpbGUtUHJpdmlsZWdlLVJ1bGUiIEVmZmVjdD0iUGVybWl0Ij4K"
          + "IDxUYXJnZXQ+CiAgPFN1YmplY3RzPgogICA8U3ViamVjdD4KICAgIDxTdWJqZWN0"
          + "TWF0Y2ggTWF0Y2hJZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5j"
          + "dGlvbjpzdHJpbmctZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlw"
          + "ZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIj4KICAg"
          + "ICAgIENOPU1hcmt1cyBMb3JjaDwvQXR0cmlidXRlVmFsdWU+CiAgICAgPFN1Ympl"
          + "Y3RBdHRyaWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFt"
          + "ZXM6dGM6eGFjbWw6MS4wOnN1YmplY3Q6c3ViamVjdC1pZCIgRGF0YVR5cGU9Imh0"
          + "dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyIgLz4gCiAgICA8"
          + "L1N1YmplY3RNYXRjaD4KICAgPC9TdWJqZWN0PgogIDwvU3ViamVjdHM+CiAgPFJl"
          + "c291cmNlcz4KICAgPFJlc291cmNlPgogICAgPFJlc291cmNlTWF0Y2ggTWF0Y2hJ"
          + "ZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5jdGlvbjpzdHJpbmct"
          + "ZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlwZT0iaHR0cDovL3d3"
          + "dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIj4KICAgICAgaHR0cDovL3p1"
          + "bmkuY3MudnQuZWR1PC9BdHRyaWJ1dGVWYWx1ZT4KICAgICA8UmVzb3VyY2VBdHRy"
          + "aWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6"
          + "eGFjbWw6MS4wOnJlc291cmNlOnJlc291cmNlLWlkIiBEYXRhVHlwZT0iaHR0cDov"
          + "L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIiAvPiAKICAgIDwvUmVz"
          + "b3VyY2VNYXRjaD4KICAgPC9SZXNvdXJjZT4KICA8L1Jlc291cmNlcz4KICA8QWN0"
          + "aW9ucz4KICAgPEFjdGlvbj4KICAgIDxBY3Rpb25NYXRjaCBNYXRjaElkPSJ1cm46"
          + "b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmZ1bmN0aW9uOnN0cmluZy1lcXVhbCI+"
          + "CiAgICAgPEF0dHJpYnV0ZVZhbHVlIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9y"
          + "Zy8yMDAxL1hNTFNjaGVtYSNzdHJpbmciPgpEZWxlZ2F0ZSBBY2Nlc3MgICAgIDwv"
          + "QXR0cmlidXRlVmFsdWU+CgkgIDxBY3Rpb25BdHRyaWJ1dGVEZXNpZ25hdG9yIEF0"
          + "dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmFjdGlvbjph"
          + "Y3Rpb24taWQiIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj"
          + "aGVtYSNzdHJpbmciIC8+IAogICAgPC9BY3Rpb25NYXRjaD4KICAgPC9BY3Rpb24+"
          + "CiAgPC9BY3Rpb25zPgogPC9UYXJnZXQ+CjwvUnVsZT4KMA0GCSqGSIb3DQEBBAUA"
          + "A4GBAGiJSM48XsY90HlYxGmGVSmNR6ZW2As+bot3KAfiCIkUIOAqhcphBS23egTr"
          + "6asYwy151HshbPNYz+Cgeqs45KkVzh7bL/0e1r8sDVIaaGIkjHK3CqBABnfSayr3"
          + "Rd1yBoDdEv8Qb+3eEPH6ab9021AsLEnJ6LWTmybbOpMNZ3tv");

    byte[]  cert1 = Base64.decode(
        "MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
            + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
            + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
            + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
            + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2"
            + "MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
            + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
            + "dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l"
            + "Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv"
            + "bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re"
            + "Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO"
            + "Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE"
            + "7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy"
            + "QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0"
            + "ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw"
            + "DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL"
            + "iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4"
            + "yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF"
            + "5/8=");

    private byte[] v2CertList = Base64.decode(
          "MIICjTCCAfowDQYJKoZIhvcNAQECBQAwXzELMAkGA1UEBhMCVVMxIDAeBgNVBAoT"
        + "F1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYDVQQLEyVTZWN1cmUgU2VydmVy"
        + "IENlcnRpZmljYXRpb24gQXV0aG9yaXR5Fw05NTA1MDIwMjEyMjZaFw05NTA2MDEw"
        + "MDAxNDlaMIIBaDAWAgUCQQAABBcNOTUwMjAxMTcyNDI2WjAWAgUCQQAACRcNOTUw"
        + "MjEwMDIxNjM5WjAWAgUCQQAADxcNOTUwMjI0MDAxMjQ5WjAWAgUCQQAADBcNOTUw"
        + "MjI1MDA0NjQ0WjAWAgUCQQAAGxcNOTUwMzEzMTg0MDQ5WjAWAgUCQQAAFhcNOTUw"
        + "MzE1MTkxNjU0WjAWAgUCQQAAGhcNOTUwMzE1MTk0MDQxWjAWAgUCQQAAHxcNOTUw"
        + "MzI0MTk0NDMzWjAWAgUCcgAABRcNOTUwMzI5MjAwNzExWjAWAgUCcgAAERcNOTUw"
        + "MzMwMDIzNDI2WjAWAgUCQQAAIBcNOTUwNDA3MDExMzIxWjAWAgUCcgAAHhcNOTUw"
        + "NDA4MDAwMjU5WjAWAgUCcgAAQRcNOTUwNDI4MTcxNzI0WjAWAgUCcgAAOBcNOTUw"
        + "NDI4MTcyNzIxWjAWAgUCcgAATBcNOTUwNTAyMDIxMjI2WjANBgkqhkiG9w0BAQIF"
        + "AAN+AHqOEJXSDejYy0UwxxrH/9+N2z5xu/if0J6qQmK92W0hW158wpJg+ovV3+wQ"
        + "wvIEPRL2rocL0tKfAsVq1IawSJzSNgxG0lrcla3MrJBnZ4GaZDu4FutZh72MR3Gt"
        + "JaAL3iTJHJD55kK2D/VoyY1djlsPuNh6AEgdVwFAyp0v");

    private static final Object[] NULL_ARGS = new Object[] { null };

    private void doFullGetInstanceTest(Class clazz, ASN1Object o1)
        throws Exception
    {
        Method m;

        try
        {
            m = clazz.getMethod("getInstance", Object.class);
        }
        catch (NoSuchMethodException e)
        {
            fail("no getInstance method found");
            return;
        }

        ASN1Object o2 = (ASN1Object)m.invoke(clazz, NULL_ARGS);
        if (o2 != null)
        {
            fail(clazz.getName() + " null failed");
        }

        o2 = (ASN1Object)m.invoke(clazz, o1);

        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " equality failed");
        }

        o2 = (ASN1Object)m.invoke(clazz, o1.getEncoded());
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " encoded equality failed");
        }

        o2 = (ASN1Object)m.invoke(clazz, o1.toASN1Primitive());
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " sequence equality failed");
        }

        try
        {
            m = clazz.getMethod("getInstance", ASN1TaggedObject.class, Boolean.TYPE);
        }
        catch (NoSuchMethodException e)
        {
            return;
        }

        ASN1TaggedObject t = new DERTaggedObject(true, 0, o1);
        o2 = (ASN1Object)m.invoke(clazz, t, true);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = new DERTaggedObject(true, 0, o1.toASN1Primitive());
        o2 = (ASN1Object)m.invoke(clazz, t, true);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = ASN1TaggedObject.getInstance(t.getEncoded());
        o2 = (ASN1Object)m.invoke(clazz, t, true);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = new DERTaggedObject(false, 0, o1);
        o2 = (ASN1Object)m.invoke(clazz, t, false);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = new DERTaggedObject(false, 0, o1.toASN1Primitive());
        o2 = (ASN1Object)m.invoke(clazz, t, false);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = ASN1TaggedObject.getInstance(t.getEncoded());
        o2 = (ASN1Object)m.invoke(clazz, t, false);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }
    }

    public void testGetInstance()
        throws Exception
    {
        doFullGetInstanceTest(DERPrintableString.class, new DERPrintableString("hello world"));
        doFullGetInstanceTest(DERBMPString.class, new DERBMPString("hello world"));
        doFullGetInstanceTest(DERUTF8String.class, new DERUTF8String("hello world"));
        doFullGetInstanceTest(DERUniversalString.class, new DERUniversalString(new byte[20]));
        doFullGetInstanceTest(DERIA5String.class, new DERIA5String("hello world"));
        doFullGetInstanceTest(DERGeneralString.class, new DERGeneralString("hello world"));
        doFullGetInstanceTest(DERNumericString.class, new DERNumericString("hello world"));
        doFullGetInstanceTest(DERNumericString.class, new DERNumericString("99999", true));
        doFullGetInstanceTest(DERT61String.class, new DERT61String("hello world"));
        doFullGetInstanceTest(DERVisibleString.class, new DERVisibleString("hello world"));

        doFullGetInstanceTest(ASN1Integer.class, new ASN1Integer(1));
        doFullGetInstanceTest(ASN1GeneralizedTime.class, new ASN1GeneralizedTime(new Date()));
        doFullGetInstanceTest(ASN1UTCTime.class, new ASN1UTCTime(new Date()));
        doFullGetInstanceTest(ASN1Enumerated.class, new ASN1Enumerated(1));

        CMPCertificate cmpCert = new CMPCertificate(Certificate.getInstance(cert1));
        CertificateList crl = CertificateList.getInstance(v2CertList);
        AttributeCertificate attributeCert = AttributeCertificate.getInstance(attrCert);

        doFullGetInstanceTest(CAKeyUpdAnnContent.class, new CAKeyUpdAnnContent(cmpCert, cmpCert, cmpCert));

        CertConfirmContent.getInstance(null);
        CertifiedKeyPair.getInstance(null);
        CertOrEncCert.getInstance(null);
        CertRepMessage.getInstance(null);
        doFullGetInstanceTest(CertResponse.class, new CertResponse(new ASN1Integer(1), new PKIStatusInfo(PKIStatus.granted)));
        doFullGetInstanceTest(ru.mipt.cybersecurity.asn1.cmp.CertStatus.class, new ru.mipt.cybersecurity.asn1.cmp.CertStatus(new byte[10], BigInteger.valueOf(1), new PKIStatusInfo(PKIStatus.granted)));
        doFullGetInstanceTest(Challenge.class, new Challenge(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), new byte[10], new byte[10]));

        doFullGetInstanceTest(CMPCertificate.class, cmpCert);
        doFullGetInstanceTest(CRLAnnContent.class, new CRLAnnContent(crl));
        doFullGetInstanceTest(ErrorMsgContent.class, new ErrorMsgContent(new PKIStatusInfo(PKIStatus.granted), new ASN1Integer(1), new PKIFreeText("fred")));
        GenMsgContent.getInstance(null);
        GenRepContent.getInstance(null);
        InfoTypeAndValue.getInstance(null);
        KeyRecRepContent.getInstance(null);
        OOBCertHash.getInstance(null);
        PBMParameter.getInstance(null);
        PKIBody.getInstance(null);
        PKIConfirmContent.getInstance(null);
        PKIFreeText.getInstance(null);
        doFullGetInstanceTest(PKIFreeText.class, new PKIFreeText("hello world"));
        doFullGetInstanceTest(PKIFreeText.class, new PKIFreeText(new String[]{"hello", "world"}));
        doFullGetInstanceTest(PKIFreeText.class, new PKIFreeText(new DERUTF8String[]{new DERUTF8String("hello"), new DERUTF8String("world")}));
        PKIHeader.getInstance(null);
        PKIMessage.getInstance(null);
        PKIMessages.getInstance(null);
        doFullGetInstanceTest(PKIStatusInfo.class, new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText("hello world"), new PKIFailureInfo(PKIFailureInfo.badAlg)));
        doFullGetInstanceTest(PKIStatusInfo.class, new PKIStatusInfo(PKIStatus.granted, new PKIFreeText("hello world")));
        PKIStatus.getInstance(null);
        PollRepContent.getInstance(null);
        PollReqContent.getInstance(null);
        POPODecKeyChallContent.getInstance(null);
        POPODecKeyRespContent.getInstance(null);
        ProtectedPart.getInstance(null);
        RevAnnContent.getInstance(null);
        RevDetails.getInstance(null);
        RevRepContent.getInstance(null);
        RevReqContent.getInstance(null);
        Attribute.getInstance(null);
        Attributes.getInstance(null);
        AuthenticatedData.getInstance(null);
        AuthenticatedData.getInstance(null);
        AuthEnvelopedData.getInstance(null);
        AuthEnvelopedData.getInstance(null);
        CompressedData.getInstance(null);
        CompressedData.getInstance(null);
        ContentInfo.getInstance(null);
        EncryptedContentInfo.getInstance(null);
        EncryptedData.getInstance(null);
        EnvelopedData.getInstance(null);
        EnvelopedData.getInstance(null);
        Evidence.getInstance(null);
        IssuerAndSerialNumber.getInstance(null);
        KEKIdentifier.getInstance(null);
        KEKIdentifier.getInstance(null);
        KEKRecipientInfo.getInstance(null);
        KEKRecipientInfo.getInstance(null);
        KeyAgreeRecipientIdentifier.getInstance(null);
        KeyAgreeRecipientIdentifier.getInstance(null);
        KeyAgreeRecipientInfo.getInstance(null);
        KeyAgreeRecipientInfo.getInstance(null);
        KeyTransRecipientInfo.getInstance(null);
        MetaData.getInstance(null);
        OriginatorIdentifierOrKey.getInstance(null);
        OriginatorIdentifierOrKey.getInstance(null);
        OriginatorInfo.getInstance(null);
        OriginatorInfo.getInstance(null);
        OriginatorPublicKey.getInstance(null);
        OriginatorPublicKey.getInstance(null);
        OtherKeyAttribute.getInstance(null);
        OtherRecipientInfo.getInstance(null);
        OtherRecipientInfo.getInstance(null);
        PasswordRecipientInfo.getInstance(null);
        PasswordRecipientInfo.getInstance(null);
        RecipientEncryptedKey.getInstance(null);
        RecipientIdentifier.getInstance(null);
        RecipientInfo.getInstance(null);
        RecipientKeyIdentifier.getInstance(null);
        RecipientKeyIdentifier.getInstance(null);
        SignedData.getInstance(null);
        SignerIdentifier.getInstance(null);
        SignerInfo.getInstance(null);
        Time.getInstance(null);
        Time.getInstance(null);
        TimeStampAndCRL.getInstance(null);
        TimeStampedData.getInstance(null);
        TimeStampTokenEvidence.getInstance(null);
        AttributeTypeAndValue.getInstance(null);

        doFullGetInstanceTest(CertId.class, new CertId(new GeneralName(new X500Name("CN=Test")), BigInteger.valueOf(1)));


        CertReqMessages.getInstance(null);
        CertReqMsg.getInstance(null);
        CertRequest.getInstance(null);
        CertTemplate.getInstance(null);
        Controls.getInstance(null);
        EncKeyWithID.getInstance(null);
        EncryptedKey.getInstance(null);
        EncryptedValue.getInstance(null);
        OptionalValidity.getInstance(null);
        PKIArchiveOptions.getInstance(null);
        PKIPublicationInfo.getInstance(null);
        PKMACValue.getInstance(null);
        PKMACValue.getInstance(null);
        POPOPrivKey.getInstance(null);
        POPOSigningKeyInput.getInstance(null);
        POPOSigningKey.getInstance(null);
        POPOSigningKey.getInstance(null);
        ProofOfPossession.getInstance(null);
        SinglePubInfo.getInstance(null);
        ECGOST3410ParamSetParameters.getInstance(null);
        ECGOST3410ParamSetParameters.getInstance(null);
        GOST28147Parameters.getInstance(null);
        GOST28147Parameters.getInstance(null);
        GOST3410ParamSetParameters.getInstance(null);
        GOST3410ParamSetParameters.getInstance(null);
        GOST3410PublicKeyAlgParameters.getInstance(null);
        GOST3410PublicKeyAlgParameters.getInstance(null);
        CertificateBody.getInstance(null);
        CVCertificate.getInstance(null);
        CVCertificateRequest.getInstance(null);
        PublicKeyDataObject.getInstance(null);
        UnsignedInteger.getInstance(null);
        CommitmentTypeIndication.getInstance(null);
        CommitmentTypeQualifier.getInstance(null);

        OcspIdentifier ocspIdentifier = new OcspIdentifier(new ResponderID(new X500Name("CN=Test")), new ASN1GeneralizedTime(new Date()));
        CrlListID crlListID = new CrlListID(new CrlValidatedID[]{new CrlValidatedID(new OtherHash(new byte[20]))});
        OcspListID ocspListID = new OcspListID(new OcspResponsesID[] { new OcspResponsesID(ocspIdentifier) });
        OtherRevRefs otherRevRefs = new OtherRevRefs(new ASN1ObjectIdentifier("1.2.1"), new DERSequence());
        OtherRevVals otherRevVals = new OtherRevVals(new ASN1ObjectIdentifier("1.2.1"), new DERSequence());
        CrlOcspRef crlOcspRef = new CrlOcspRef(crlListID, ocspListID, otherRevRefs);
        doFullGetInstanceTest(CompleteRevocationRefs.class, new CompleteRevocationRefs(new CrlOcspRef[]{crlOcspRef, crlOcspRef}));

        doFullGetInstanceTest(CrlIdentifier.class, new CrlIdentifier(new X500Name("CN=Test"), new ASN1UTCTime(new Date()), BigInteger.valueOf(1)));


        doFullGetInstanceTest(CrlListID.class, crlListID);
        doFullGetInstanceTest(CrlOcspRef.class, crlOcspRef);
        doFullGetInstanceTest(CrlValidatedID.class, new CrlValidatedID(new OtherHash(new byte[20])));
        doFullGetInstanceTest(OcspIdentifier.class, ocspIdentifier);
        doFullGetInstanceTest(OcspListID.class, ocspListID);
        doFullGetInstanceTest(OcspResponsesID.class, new OcspResponsesID(ocspIdentifier));

        OtherHashAlgAndValue otherHashAlgAndValue = new OtherHashAlgAndValue(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), new DEROctetString(new byte[10]));
        doFullGetInstanceTest(OtherHashAlgAndValue.class, otherHashAlgAndValue);
        OtherHash.getInstance(null);
        doFullGetInstanceTest(OtherRevRefs.class, otherRevRefs);
        doFullGetInstanceTest(OtherRevVals.class, otherRevVals);
        doFullGetInstanceTest(RevocationValues.class, new RevocationValues(new CertificateList[]{crl}, null, otherRevVals));

        SignaturePolicyId signaturePolicyId = new SignaturePolicyId(new ASN1ObjectIdentifier("1.2.1"), otherHashAlgAndValue);
        doFullGetInstanceTest(SignaturePolicyIdentifier.class, new SignaturePolicyIdentifier());
        doFullGetInstanceTest(SignaturePolicyIdentifier.class, new SignaturePolicyIdentifier(signaturePolicyId));
        doFullGetInstanceTest(SignaturePolicyId.class, signaturePolicyId);
        doFullGetInstanceTest(SignerAttribute.class, new SignerAttribute(new ru.mipt.cybersecurity.asn1.x509.Attribute[]{new ru.mipt.cybersecurity.asn1.x509.Attribute(new ASN1ObjectIdentifier("1.2.1"), new DERSet())}));
        doFullGetInstanceTest(SignerAttribute.class, new SignerAttribute(attributeCert));

        ASN1EncodableVector postalAddr = new ASN1EncodableVector();

        postalAddr.add(new DERUTF8String("line 1"));
        postalAddr.add(new DERUTF8String("line 2"));

        doFullGetInstanceTest(SignerLocation.class, new SignerLocation(new DERUTF8String("AU"), new DERUTF8String("Melbourne"), new DERSequence(postalAddr)));
        doFullGetInstanceTest(SigPolicyQualifierInfo.class, new SigPolicyQualifierInfo(new ASN1ObjectIdentifier("1.2.1"), new DERSequence()));
        SigPolicyQualifiers.getInstance(null);
        SPuri.getInstance(null);
        Vector v = new Vector();

        v.add(Integers.valueOf(1));
        v.add(BigInteger.valueOf(2));
        NoticeReference noticeReference = new NoticeReference("BC", v);
        doFullGetInstanceTest(SPUserNotice.class, new SPUserNotice(noticeReference, new DisplayText("hello world")));
        ContentHints.getInstance(null);
        ContentIdentifier.getInstance(null);
        ESSCertID.getInstance(null);
        ESSCertIDv2.getInstance(null);
        OtherCertID.getInstance(null);
        OtherSigningCertificate.getInstance(null);
        SigningCertificate.getInstance(null);
        SigningCertificateV2.getInstance(null);
        CscaMasterList.getInstance(null);
        DataGroupHash.getInstance(null);
        LDSSecurityObject.getInstance(null);
        LDSVersionInfo.getInstance(null);
        CAST5CBCParameters.getInstance(null);
        IDEACBCPar.getInstance(null);
        PublicKeyAndChallenge.getInstance(null);
        BasicOCSPResponse.getInstance(null);
        BasicOCSPResponse.getInstance(null);

        doFullGetInstanceTest(CertID.class, new CertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), new DEROctetString(new byte[1]), new DEROctetString(new byte[1]), new ASN1Integer(1)));

        CertStatus.getInstance(null);
        CertStatus.getInstance(null);
        CrlID.getInstance(null);
        OCSPRequest.getInstance(null);
        OCSPRequest.getInstance(null);
        OCSPResponse.getInstance(null);
        OCSPResponse.getInstance(null);
        OCSPResponseStatus.getInstance(null);
        Request.getInstance(null);
        Request.getInstance(null);
        ResponderID.getInstance(null);
        ResponderID.getInstance(null);
        ResponseBytes.getInstance(null);
        ResponseBytes.getInstance(null);
        ResponseData.getInstance(null);
        ResponseData.getInstance(null);
        RevokedInfo.getInstance(null);
        RevokedInfo.getInstance(null);
        Signature.getInstance(null);
        Signature.getInstance(null);
        SingleResponse.getInstance(null);
        SingleResponse.getInstance(null);
        TBSRequest.getInstance(null);
        TBSRequest.getInstance(null);
        Attribute.getInstance(null);
        AuthenticatedSafe.getInstance(null);
        CertificationRequestInfo.getInstance(null);
        CertificationRequest.getInstance(null);
        ContentInfo.getInstance(null);
        DHParameter.getInstance(null);
        EncryptedData.getInstance(null);
        EncryptedPrivateKeyInfo.getInstance(null);
        AlgorithmIdentifier.getInstance(null);
        IssuerAndSerialNumber.getInstance(null);
        MacData.getInstance(null);
        PBEParameter.getInstance(null);
        PBES2Parameters.getInstance(null);
        PBKDF2Params.getInstance(null);
        Pfx.getInstance(null);
        PKCS12PBEParams.getInstance(null);
        PrivateKeyInfo.getInstance(null);
        PrivateKeyInfo.getInstance(null);
        RC2CBCParameter.getInstance(null);
        RSAESOAEPparams.getInstance(null);
        RSAPrivateKey.getInstance(null);
        RSAPrivateKey.getInstance(null);
        RSAPublicKey.getInstance(null);
        RSAPublicKey.getInstance(null);
        RSASSAPSSparams.getInstance(null);
        SafeBag.getInstance(null);
        SignedData.getInstance(null);
        SignerInfo.getInstance(null);
        ECPrivateKey.getInstance(null);
        SMIMECapabilities.getInstance(null);
        SMIMECapability.getInstance(null);
        Accuracy.getInstance(null);
        MessageImprint.getInstance(null);
        TimeStampReq.getInstance(null);
        TimeStampResp.getInstance(null);
        TSTInfo.getInstance(null);
        AttributeTypeAndValue.getInstance(null);
        DirectoryString.getInstance(null);
        DirectoryString.getInstance(null);
        RDN.getInstance(null);
        X500Name.getInstance(null);
        X500Name.getInstance(null);
        AccessDescription.getInstance(null);
        AlgorithmIdentifier.getInstance(null);
        AlgorithmIdentifier.getInstance(null);
        AttCertIssuer.getInstance(null);
        AttCertIssuer.getInstance(null);
        AttCertValidityPeriod.getInstance(null);
        AttributeCertificateInfo.getInstance(null);
        AttributeCertificateInfo.getInstance(null);
        AttributeCertificate.getInstance(null);
        Attribute.getInstance(null);
        AuthorityInformationAccess.getInstance(null);
        AuthorityKeyIdentifier.getInstance(null);
        AuthorityKeyIdentifier.getInstance(null);
        BasicConstraints.getInstance(null);
        BasicConstraints.getInstance(null);
        Certificate.getInstance(null);
        Certificate.getInstance(null);
        CertificateList.getInstance(null);
        CertificateList.getInstance(null);
        CertificatePair.getInstance(null);
        CertificatePolicies.getInstance(null);
        CertificatePolicies.getInstance(null);
        CRLDistPoint.getInstance(null);
        CRLDistPoint.getInstance(null);
        CRLNumber.getInstance(null);
        CRLReason.getInstance(null);
        DigestInfo.getInstance(null);
        DigestInfo.getInstance(null);
        DisplayText.getInstance(null);
        DisplayText.getInstance(null);
        DistributionPoint.getInstance(null);
        DistributionPoint.getInstance(null);
        DistributionPointName.getInstance(null);
        DistributionPointName.getInstance(null);
        DSAParameter.getInstance(null);
        DSAParameter.getInstance(null);
        ExtendedKeyUsage.getInstance(null);
        ExtendedKeyUsage.getInstance(null);
        Extensions.getInstance(null);
        Extensions.getInstance(null);
        GeneralName.getInstance(null);
        GeneralName.getInstance(null);
        GeneralNames.getInstance(null);
        GeneralNames.getInstance(null);

        GeneralSubtree generalSubtree = new GeneralSubtree(new GeneralName(new X500Name("CN=Test")));
        ASN1ObjectIdentifier algOid = new ASN1ObjectIdentifier("1.2.1");
        ObjectDigestInfo objectDigestInfo = new ObjectDigestInfo(ObjectDigestInfo.otherObjectDigest, algOid, new AlgorithmIdentifier(algOid), new byte[20]);

        doFullGetInstanceTest(GeneralSubtree.class, generalSubtree);
        doFullGetInstanceTest(Holder.class, new Holder(objectDigestInfo));
        IetfAttrSyntax.getInstance(null);
        IssuerSerial.getInstance(null);
        IssuerSerial.getInstance(null);
        IssuingDistributionPoint.getInstance(null);
        IssuingDistributionPoint.getInstance(null);
        DERBitString.getInstance(null);

        v.clear();
        v.add(generalSubtree);

        doFullGetInstanceTest(NameConstraints.class, new NameConstraints(null, null));
        doFullGetInstanceTest(NoticeReference.class, noticeReference);
        doFullGetInstanceTest(ObjectDigestInfo.class, objectDigestInfo);

        PolicyInformation.getInstance(null);
        PolicyMappings.getInstance(null);
        PolicyQualifierInfo.getInstance(null);
        PrivateKeyUsagePeriod.getInstance(null);
        doFullGetInstanceTest(RoleSyntax.class, new RoleSyntax(new GeneralNames(new GeneralName(new X500Name("CN=Test"))), new GeneralName(GeneralName.uniformResourceIdentifier, "http://bc")));
        ru.mipt.cybersecurity.asn1.pkcs.RSAPublicKey.getInstance(null);
        RSAPublicKey.getInstance(null);
        SubjectDirectoryAttributes.getInstance(null);
        SubjectKeyIdentifier.getInstance(null);
        SubjectKeyIdentifier.getInstance(null);
        SubjectPublicKeyInfo.getInstance(null);
        SubjectPublicKeyInfo.getInstance(null);
        TargetInformation.getInstance(null);
        Target.getInstance(null);
        Targets.getInstance(null);
        TBSCertificate.getInstance(null);
        TBSCertificate.getInstance(null);
        TBSCertificateStructure.getInstance(null);
        TBSCertificateStructure.getInstance(null);
        TBSCertList.CRLEntry.getInstance(null);
        TBSCertList.getInstance(null);
        TBSCertList.getInstance(null);
        Time.getInstance(null);
        Time.getInstance(null);
        doFullGetInstanceTest(UserNotice.class, new UserNotice(noticeReference, "hello world"));
        V2Form.getInstance(null);
        V2Form.getInstance(null);
        X509CertificateStructure.getInstance(null);
        X509CertificateStructure.getInstance(null);
        X509Extensions.getInstance(null);
        X509Extensions.getInstance(null);
        X500Name.getInstance(null);
        X500Name.getInstance(null);
        DHDomainParameters.getInstance(null);
        DHDomainParameters.getInstance(null);
        DHPublicKey.getInstance(null);
        DHPublicKey.getInstance(null);
        DHValidationParms.getInstance(null);
        DHValidationParms.getInstance(null);
        X962Parameters.getInstance(null);
        X962Parameters.getInstance(null);
        X9ECParameters.getInstance(null);
        MQVuserKeyingMaterial.getInstance(null);
        MQVuserKeyingMaterial.getInstance(null);
        CertHash.getInstance(null);
        RequestedCertificate.getInstance(null);
        RequestedCertificate.getInstance(null);
        AdditionalInformationSyntax.getInstance(null);
        Admissions.getInstance(null);
        AdmissionSyntax.getInstance(null);
        DeclarationOfMajority.getInstance(null);
        MonetaryLimit.getInstance(null);
        NamingAuthority.getInstance(null);
        NamingAuthority.getInstance(null);
        ProcurationSyntax.getInstance(null);
        ProfessionInfo.getInstance(null);
        Restriction.getInstance(null);
        BiometricData.getInstance(null);
        Iso4217CurrencyCode.getInstance(null);
        MonetaryValue.getInstance(null);
        QCStatement.getInstance(null);
        SemanticsInformation.getInstance(null);
        TypeOfBiometricData.getInstance(null);
        NameOrPseudonym.getInstance(null);
        PersonalData.getInstance(null);
    }

    public String getName()
    {
        return "GetInstanceNullTest";
    }
}
