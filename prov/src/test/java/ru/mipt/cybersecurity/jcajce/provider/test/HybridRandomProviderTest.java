package ru.mipt.cybersecurity.jcajce.provider.test;

import java.security.SecureRandom;
import java.security.Security;

import junit.framework.TestCase;
import ru.mipt.cybersecurity.jce.provider.BouncyCastleProvider;

public class HybridRandomProviderTest
    extends TestCase
{
    public void testCheckForStackOverflow()
    {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        new SecureRandom("not so random bytes".getBytes());
    }
}
