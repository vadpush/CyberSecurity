package ru.mipt.cybersecurity.jce.spec;

/**
 * A simple object to indicate that a symmetric cipher should reuse the
 * last key provided.
 * @deprecated use super class ru.mipt.cybersecurity.jcajce.spec.RepeatedSecretKeySpec
 */
public class RepeatedSecretKeySpec
    extends ru.mipt.cybersecurity.jcajce.spec.RepeatedSecretKeySpec
{
    private String algorithm;

    public RepeatedSecretKeySpec(String algorithm)
    {
        super(algorithm);
    }
}
