package ru.mipt.cybersecurity.crypto.prng.test;

import ru.mipt.cybersecurity.util.test.Test;
import ru.mipt.cybersecurity.util.test.TestResult;

public class RegressionTest
{
    public static Test[]    tests = {
        new CTRDRBGTest(),
        new DualECDRBGTest(),
        new HashDRBGTest(),
        new HMacDRBGTest(),
        new SP800RandomTest(),
        new X931Test(),
        new FixedSecureRandomTest()
    };

    public static void main(
        String[]    args)
    {
        for (int i = 0; i != tests.length; i++)
        {
            TestResult  result = tests[i].perform();
            
            if (result.getException() != null)
            {
                result.getException().printStackTrace();
            }
            
            System.out.println(result);
        }
    }
}

