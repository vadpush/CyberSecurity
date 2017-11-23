package ru.mipt.cybersecurity.jce.interfaces;

import javax.crypto.interfaces.DHKey;

import ru.mipt.cybersecurity.jce.spec.ElGamalParameterSpec;

public interface ElGamalKey
    extends DHKey
{
    public ElGamalParameterSpec getParameters();
}
