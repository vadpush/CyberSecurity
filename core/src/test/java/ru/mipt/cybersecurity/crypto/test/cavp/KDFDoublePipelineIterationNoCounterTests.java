package ru.mipt.cybersecurity.crypto.test.cavp;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Properties;

import ru.mipt.cybersecurity.crypto.Mac;
import ru.mipt.cybersecurity.crypto.generators.KDFDoublePipelineIterationBytesGenerator;
import ru.mipt.cybersecurity.crypto.params.KDFDoublePipelineIterationParameters;
import ru.mipt.cybersecurity.util.Arrays;
import ru.mipt.cybersecurity.util.encoders.Hex;
import ru.mipt.cybersecurity.util.test.SimpleTestResult;
import ru.mipt.cybersecurity.util.test.TestFailedException;

public final class KDFDoublePipelineIterationNoCounterTests
    implements CAVPListener
{
    private PrintWriter out;

    public void receiveCAVPVectors(String name, Properties config,
                                   Properties vectors)
    {


        // create Mac based PRF from PRF property, create the KDF
        final Mac prf = CAVPReader.createPRF(config);
        final KDFDoublePipelineIterationBytesGenerator gen = new KDFDoublePipelineIterationBytesGenerator(prf);

        final int count = Integer.parseInt(vectors.getProperty("COUNT"));
        final int l = Integer.parseInt(vectors.getProperty("L"));
        final byte[] ki = Hex.decode(vectors.getProperty("KI"));
        final byte[] fixedInputData = Hex.decode(vectors.getProperty("FixedInputData"));
        final KDFDoublePipelineIterationParameters params = KDFDoublePipelineIterationParameters.createWithoutCounter(ki, fixedInputData);
        gen.init(params);

        final byte[] koGenerated = new byte[l / 8];
        gen.generateBytes(koGenerated, 0, koGenerated.length);

        final byte[] koVectors = Hex.decode(vectors.getProperty("KO"));

        compareKO(name, config, count, koGenerated, koVectors);
    }

    private static void compareKO(
        String name, Properties config, int test, byte[] calculatedOKM, byte[] testOKM)
    {

        if (!Arrays.areEqual(calculatedOKM, testOKM))
        {
            throw new TestFailedException(new SimpleTestResult(
                false, name + " using " + config + " test " + test + " failed"));

        }
    }

    public void receiveCommentLine(String commentLine)
    {
        //                out.println("# " + commentLine);
    }

    public void receiveStart(String name)
    {
        // do nothing
    }

    public void receiveEnd()
    {
        out.println(" *** *** *** ");
    }

    public void setup()
    {
        try
        {
            out = new PrintWriter(new FileWriter("KDFDblPipelineNoCounter.gen"));
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e);
        }
    }

    public void tearDown()
    {
        out.close();
    }
}