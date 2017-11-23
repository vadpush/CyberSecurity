package ru.mipt.cybersecurity.jcajce.provider.config;

import java.util.Map;
import java.util.Set;

import javax.crypto.spec.DHParameterSpec;

import ru.mipt.cybersecurity.jce.spec.ECParameterSpec;

public interface ProviderConfiguration
{
    ECParameterSpec getEcImplicitlyCa();

    DHParameterSpec getDHDefaultParameters(int keySize);

    Set getAcceptableNamedCurves();

    Map getAdditionalECParameters();
}
