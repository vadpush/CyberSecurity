package ru.mipt.cybersecurity.math.field;

public interface ExtensionField extends FiniteField
{
    FiniteField getSubfield();

    int getDegree();
}
