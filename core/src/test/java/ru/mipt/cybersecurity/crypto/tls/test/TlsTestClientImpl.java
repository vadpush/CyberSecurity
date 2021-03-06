package ru.mipt.cybersecurity.crypto.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Hashtable;
import java.util.Vector;

import ru.mipt.cybersecurity.asn1.ASN1EncodableVector;
import ru.mipt.cybersecurity.asn1.DERBitString;
import ru.mipt.cybersecurity.asn1.DERSequence;
import ru.mipt.cybersecurity.asn1.x509.Certificate;
import ru.mipt.cybersecurity.crypto.tls.AlertDescription;
import ru.mipt.cybersecurity.crypto.tls.AlertLevel;
import ru.mipt.cybersecurity.crypto.tls.CertificateRequest;
import ru.mipt.cybersecurity.crypto.tls.ClientCertificateType;
import ru.mipt.cybersecurity.crypto.tls.ConnectionEnd;
import ru.mipt.cybersecurity.crypto.tls.DefaultTlsClient;
import ru.mipt.cybersecurity.crypto.tls.ProtocolVersion;
import ru.mipt.cybersecurity.crypto.tls.SignatureAlgorithm;
import ru.mipt.cybersecurity.crypto.tls.SignatureAndHashAlgorithm;
import ru.mipt.cybersecurity.crypto.tls.TlsAuthentication;
import ru.mipt.cybersecurity.crypto.tls.TlsCredentials;
import ru.mipt.cybersecurity.crypto.tls.TlsFatalAlert;
import ru.mipt.cybersecurity.crypto.tls.TlsSignerCredentials;
import ru.mipt.cybersecurity.crypto.tls.TlsUtils;
import ru.mipt.cybersecurity.util.Arrays;

class TlsTestClientImpl
    extends DefaultTlsClient
{
    protected final TlsTestConfig config;

    protected int firstFatalAlertConnectionEnd = -1;
    protected short firstFatalAlertDescription = -1;

    TlsTestClientImpl(TlsTestConfig config)
    {
        this.config = config;
    }

    int getFirstFatalAlertConnectionEnd()
    {
        return firstFatalAlertConnectionEnd;
    }

    short getFirstFatalAlertDescription()
    {
        return firstFatalAlertDescription;
    }

    public ProtocolVersion getClientVersion()
    {
        if (config.clientOfferVersion != null)
        {
            return config.clientOfferVersion;
        }

        return super.getClientVersion();
    }

    public ProtocolVersion getMinimumVersion()
    {
        if (config.clientMinimumVersion != null)
        {
            return config.clientMinimumVersion;
        }

        return super.getMinimumVersion();
    }

    public Hashtable getClientExtensions() throws IOException
    {
        Hashtable clientExtensions = super.getClientExtensions();
        if (clientExtensions != null && !config.clientSendSignatureAlgorithms)
        {
            clientExtensions.remove(TlsUtils.EXT_signature_algorithms);
            this.supportedSignatureAlgorithms = null;
        }
        return clientExtensions;
    }

    public boolean isFallback()
    {
        return config.clientFallback;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        if (alertLevel == AlertLevel.fatal && firstFatalAlertConnectionEnd == -1)
        {
            firstFatalAlertConnectionEnd = ConnectionEnd.client;
            firstFatalAlertDescription = alertDescription;
        }

        if (TlsTestConfig.DEBUG)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client raised alert: " + AlertLevel.getText(alertLevel)
                + ", " + AlertDescription.getText(alertDescription));
            if (message != null)
            {
                out.println("> " + message);
            }
            if (cause != null)
            {
                cause.printStackTrace(out);
            }
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        if (alertLevel == AlertLevel.fatal && firstFatalAlertConnectionEnd == -1)
        {
            firstFatalAlertConnectionEnd = ConnectionEnd.server;
            firstFatalAlertDescription = alertDescription;
        }

        if (TlsTestConfig.DEBUG)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client received alert: " + AlertLevel.getText(alertLevel)
                + ", " + AlertDescription.getText(alertDescription));
        }
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        super.notifyServerVersion(serverVersion);

        if (TlsTestConfig.DEBUG)
        {
            System.out.println("TLS client negotiated " + serverVersion);
        }
    }

    public TlsAuthentication getAuthentication()
        throws IOException
    {
        return new TlsAuthentication()
        {
            public void notifyServerCertificate(ru.mipt.cybersecurity.crypto.tls.Certificate serverCertificate)
                throws IOException
            {
                boolean isEmpty = serverCertificate == null || serverCertificate.isEmpty();

                Certificate[] chain = serverCertificate.getCertificateList();

                // TODO Cache test resources?
                if (isEmpty || !(chain[0].equals(TlsTestUtils.loadCertificateResource("x509-server.pem"))
                    || chain[0].equals(TlsTestUtils.loadCertificateResource("x509-server-dsa.pem"))
                    || chain[0].equals(TlsTestUtils.loadCertificateResource("x509-server-ecdsa.pem"))))
                {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                if (TlsTestConfig.DEBUG)
                {
                    System.out.println("TLS client received server certificate chain of length " + chain.length);
                    for (int i = 0; i != chain.length; i++)
                    {
                        Certificate entry = chain[i];
                        // TODO Create fingerprint based on certificate signature algorithm digest
                        System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                            + entry.getSubject() + ")");
                    }
                }
            }

            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                throws IOException
            {
                if (config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_NONE)
                {
                    throw new IllegalStateException();
                }
                if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_NONE)
                {
                    return null;
                }

                short[] certificateTypes = certificateRequest.getCertificateTypes();
                if (certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign))
                {
                    return null;
                }

                Vector supportedSigAlgs = certificateRequest.getSupportedSignatureAlgorithms();
                if (supportedSigAlgs != null && config.clientAuthSigAlg != null)
                {
                    supportedSigAlgs = new Vector(1);
                    supportedSigAlgs.addElement(config.clientAuthSigAlg);
                }

                final TlsSignerCredentials signerCredentials = TlsTestUtils.loadSignerCredentials(context,
                    supportedSigAlgs, SignatureAlgorithm.rsa, "x509-client.pem", "x509-client-key.pem");

                if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_VALID)
                {
                    return signerCredentials;
                }

                return new TlsSignerCredentials()
                {
                    public byte[] generateCertificateSignature(byte[] hash) throws IOException
                    {
                        byte[] sig = signerCredentials.generateCertificateSignature(hash);

                        if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_VERIFY)
                        {
                            sig = corruptBit(sig);
                        }

                        return sig;
                    }

                    public ru.mipt.cybersecurity.crypto.tls.Certificate getCertificate()
                    {
                        ru.mipt.cybersecurity.crypto.tls.Certificate cert = signerCredentials.getCertificate();

                        if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_CERT)
                        {
                            cert = corruptCertificate(cert);
                        }

                        return cert;
                    }

                    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
                    {
                        return signerCredentials.getSignatureAndHashAlgorithm();
                    }
                };
            }
        };
    }

    protected ru.mipt.cybersecurity.crypto.tls.Certificate corruptCertificate(ru.mipt.cybersecurity.crypto.tls.Certificate cert)
    {
        Certificate[] certList = cert.getCertificateList();
        certList[0] = corruptCertificateSignature(certList[0]);
        return new ru.mipt.cybersecurity.crypto.tls.Certificate(certList);
    }

    protected Certificate corruptCertificateSignature(Certificate cert)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(cert.getTBSCertificate());
        v.add(cert.getSignatureAlgorithm());
        v.add(corruptSignature(cert.getSignature()));

        return Certificate.getInstance(new DERSequence(v));
    }

    protected DERBitString corruptSignature(DERBitString bs)
    {
        return new DERBitString(corruptBit(bs.getOctets()));
    }

    protected byte[] corruptBit(byte[] bs)
    {
        bs = Arrays.clone(bs);

        // Flip a random bit
        int bit = context.getSecureRandom().nextInt(bs.length << 3); 
        bs[bit >>> 3] ^= (1 << (bit & 7));

        return bs;
    }
}
