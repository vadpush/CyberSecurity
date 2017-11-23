package ru.mipt.cybersecurity.math.ec;

public interface ECLookupTable
{
    int getSize();
    ECPoint lookup(int index);
}
