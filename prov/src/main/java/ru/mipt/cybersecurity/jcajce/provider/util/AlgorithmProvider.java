package ru.mipt.cybersecurity.jcajce.provider.util;

import ru.mipt.cybersecurity.jcajce.provider.config.ConfigurableProvider;

public abstract class AlgorithmProvider
{
    public abstract void configure(ConfigurableProvider provider);
}
