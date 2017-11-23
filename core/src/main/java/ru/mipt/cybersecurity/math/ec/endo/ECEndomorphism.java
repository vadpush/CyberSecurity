package ru.mipt.cybersecurity.math.ec.endo;

import ru.mipt.cybersecurity.math.ec.ECPointMap;

public interface ECEndomorphism
{
    ECPointMap getPointMap();

    boolean hasEfficientPointMap();
}
