package ru.mipt.cybersecurity.crypto.engines;

import ru.mipt.cybersecurity.crypto.BlockCipher;
import ru.mipt.cybersecurity.crypto.CipherParameters;
import ru.mipt.cybersecurity.crypto.DataLengthException;
import ru.mipt.cybersecurity.crypto.OutputLengthException;
import ru.mipt.cybersecurity.crypto.params.KeyParameter;
import ru.mipt.cybersecurity.crypto.params.ParametersWithSBox;

/**
 * implementation of GOST 28147-14 (Kuznyechik)
 */


public class GOST28147_14Engine implements BlockCipher {
    protected static final int  BLOCK_SIZE = 16;
    private char[]               workingKey = null;
    private boolean forEncryption;



    /* Нелинейное биективное преобразование множества двоичных векторов. */
    private static char kPi[] = {
            252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250, 218,  35, 197,   4,  77,
            233, 119, 240, 219, 147,  46, 153, 186,  23,  54, 241, 187,  20, 205,  95, 193,
            249,  24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66,	139,   1, 142,  79,
            5, 132,   2, 174, 227, 106, 143, 160,   6,  11, 237, 152, 127, 212, 211,  31,
            235,  52,  44,  81,	234, 200,  72, 171, 242,  42, 104, 162, 253,  58, 206, 204,
            181, 112,  14,  86,   8,  12, 118,  18, 191, 114,  19,  71, 156, 183,  93, 135,
            21, 161, 150,  41,  16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
            50, 117,  25,  61, 255,  53, 138, 126, 109,  84, 198, 128, 195, 189,  13,  87,
            223, 245,  36, 169,  62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,   3,
            224,  15, 236, 222, 122, 148, 176, 188, 220, 232,  40,  80,  78,  51,  10,  74,
            167, 151,  96, 115,  30,   0,  98,  68,  26, 184,  56, 130, 100, 159,  38,  65,
            173,  69,  70, 146,  39,  94,  85,  47, 140, 163, 165, 125, 105, 213, 149,  59,
            7,  88, 179,  64, 134, 172,  29, 247,  48,  55, 107, 228,	136, 217, 231, 137,
            225,  27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144, 202, 216, 133,  97,
            32, 113, 103, 164,  45,  43,   9,  91, 203, 155,  37, 208, 190, 229, 108,  82,
            89, 166, 116, 210, 230, 244, 180, 192,	209, 102, 175, 194,  57,  75,  99, 182
    };

/* Обратное нелинейное биективное преобразование множества двоичных векторов. */
    private static char kReversePi[] = {
                0xa5, 0x2d, 0x32, 0x8f, 0x0e, 0x30, 0x38, 0xc0, 0x54, 0xe6, 0x9e, 0x39, 0x55, 0x7e, 0x52, 0x91,
                0x64, 0x03, 0x57, 0x5a, 0x1c, 0x60, 0x07, 0x18, 0x21, 0x72, 0xa8, 0xd1, 0x29, 0xc6, 0xa4, 0x3f,
                0xe0, 0x27, 0x8d, 0x0c, 0x82, 0xea, 0xae, 0xb4, 0x9a, 0x63, 0x49, 0xe5, 0x42, 0xe4, 0x15, 0xb7,
                0xc8, 0x06, 0x70, 0x9d, 0x41, 0x75, 0x19, 0xc9, 0xaa, 0xfc, 0x4d, 0xbf, 0x2a, 0x73, 0x84, 0xd5,
                0xc3, 0xaf, 0x2b, 0x86, 0xa7, 0xb1, 0xb2, 0x5b, 0x46, 0xd3, 0x9f, 0xfd, 0xd4, 0x0f, 0x9c, 0x2f,
                0x9b, 0x43, 0xef, 0xd9, 0x79, 0xb6, 0x53, 0x7f, 0xc1, 0xf0, 0x23, 0xe7, 0x25, 0x5e, 0xb5, 0x1e,
                0xa2, 0xdf, 0xa6, 0xfe, 0xac, 0x22, 0xf9, 0xe2, 0x4a, 0xbc, 0x35, 0xca, 0xee, 0x78, 0x05, 0x6b,
                0x51, 0xe1, 0x59, 0xa3, 0xf2, 0x71, 0x56, 0x11, 0x6a, 0x89, 0x94, 0x65, 0x8c, 0xbb, 0x77, 0x3c,
                0x7b, 0x28, 0xab, 0xd2, 0x31, 0xde, 0xc4, 0x5f, 0xcc, 0xcf, 0x76, 0x2c, 0xb8, 0xd8, 0x2e, 0x36,
                0xdb, 0x69, 0xb3, 0x14, 0x95, 0xbe, 0x62, 0xa1, 0x3b, 0x16, 0x66, 0xe9, 0x5c, 0x6c, 0x6d, 0xad,
                0x37, 0x61, 0x4b, 0xb9, 0xe3, 0xba, 0xf1, 0xa0, 0x85, 0x83, 0xda, 0x47, 0xc5, 0xb0, 0x33, 0xfa,
                0x96, 0x6f, 0x6e, 0xc2, 0xf6, 0x50, 0xff, 0x5d, 0xa9, 0x8e, 0x17, 0x1b, 0x97, 0x7d, 0xec, 0x58,
                0xf7, 0x1f, 0xfb, 0x7c, 0x09, 0x0d, 0x7a, 0x67, 0x45, 0x87, 0xdc, 0xe8, 0x4f, 0x1d, 0x4e, 0x04,
                0xeb, 0xf8, 0xf3, 0x3e, 0x3d, 0xbd, 0x8a, 0x88, 0xdd, 0xcd, 0x0b, 0x13, 0x98, 0x02, 0x93, 0x80,
                0x90, 0xd0, 0x24, 0x34, 0xcb, 0xed, 0xf4, 0xce, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3a, 0x01, 0x26,
                0x12, 0x1a, 0x48, 0x68, 0xf5, 0x81, 0x8b, 0xc7, 0xd6, 0x20, 0x0a, 0x08, 0x00, 0x4c, 0xd7, 0x74
        };

    /*Коэффициенты умножения в преобразовании l */
    private static char kB[] = {148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1};


    private void funcX( char[] a, char[] b,  char[] outdata) {
        for(int i = 0; i < BLOCK_SIZE; ++i) {
            outdata[i] = (char) (a[i] ^ b[i]);
        }
    }

    private void funcS( char[] indata,  char[] outdata) {
        for(int i = 0; i < BLOCK_SIZE; ++i)
            outdata[i] = kPi[indata[i]];
    }

    private void funcReverseS( char[] indata,  char[] outdata) {
    for(int i = 0; i < BLOCK_SIZE; ++i)
        outdata[i] = kReversePi[indata[i]];
    }

    private char multGF(char a, char b) {
        char c = 0;
        char hiBit;

        while(b != 0) {
            if((b & 1) != 0)
                c ^= a;
            hiBit = (char)(a & 0x80);
            a <<= 1;
            if (hiBit != 0)
                a ^= 0xc3;
            b >>= 1;
        }
        return (char) (c & 0xFF);
    }

    private void funcR( char[] indata, char[] outdata) {
        char sum = 0;

        for(int i = 0; i < BLOCK_SIZE; ++i)
            sum ^= multGF(indata[i], kB[i]);

        outdata[0] = sum;
        System.arraycopy(indata, 0, outdata, 1, BLOCK_SIZE-1);
    }

    private void funcReverseR(char[] indata,  char[] outdata) {
        char tmp[] = new char[BLOCK_SIZE];
        char sum = 0;

        //void *memcpy(void *dst, const void *src, size_t n);
        //System.arraycopy(Object src, int srcPos, Object dest,int destPos, int length);

        // memcpy(tmp, indata+1, 15);
        System.arraycopy(indata , 1, tmp, 0, BLOCK_SIZE-1);

        tmp[15] = indata[0];

        for(int i = 0; i < BLOCK_SIZE; ++i)
            sum ^= multGF(tmp[i], kB[i]);

        //memcpy(outdata, tmp, 15);
        System.arraycopy(tmp , 0, outdata, 0, BLOCK_SIZE-1);

        outdata[15] = sum;
    }


    private void funcL(char[] indata, char[] outdata) {
        char tmp[] = new char[BLOCK_SIZE];

        //memcpy(tmp, indata, 16);
        System.arraycopy(indata , 0, tmp, 0, BLOCK_SIZE);

        for(int i = 0; i < BLOCK_SIZE; ++i) {
            funcR(tmp, outdata);
            //memcpy(tmp, outdata, 16);
            System.arraycopy(outdata, 0, tmp, 0, BLOCK_SIZE);
        }
    }


    private void funcReverseL(char[] indata, char[] outdata) {
        char[] tmp = new char[BLOCK_SIZE];

        //memcpy(tmp, indata, 16);
        System.arraycopy(indata , 0, tmp, 0, BLOCK_SIZE);

        for(int i = 0; i < BLOCK_SIZE; ++i) {
            funcReverseR(tmp, outdata);
            //memcpy(tmp, outdata, 16);
            System.arraycopy(outdata , 0, tmp, 0, BLOCK_SIZE);
        }
    }


    private void funcLSX(char[] a, char[] b, char[] outdata) {
        char[] temp1 = new char[BLOCK_SIZE];
        char[] temp2 = new char[BLOCK_SIZE];

        funcX(a, b, temp1);
        funcS(temp1, temp2);
        funcL(temp2, outdata);
    }


    private void funcReverseLSX(char[] a, char[] b, char[] outdata) {
        char[] temp1 = new char[BLOCK_SIZE];
        char[] temp2 = new char[BLOCK_SIZE];

        funcX(a, b, temp1);
        funcReverseL(temp1, temp2);
        funcReverseS(temp2, outdata);
    }

    private void funcF(char[] inputKey, char[] inputKeySecond, char[] iterationConst, char[] outputKey, char[] outputKeySecond) {
        char[] temp1 = new char[BLOCK_SIZE];
        char[] temp2 = new char[BLOCK_SIZE];

        funcLSX(inputKey, iterationConst, temp1);
        funcX(temp1, inputKeySecond, temp2);

        //memcpy(outputKeySecond, inputKey, 16);
        System.arraycopy(inputKey , 0, outputKeySecond, 0, BLOCK_SIZE);

        //memcpy(outputKey, temp2, 16);
        System.arraycopy(temp2 , 0, outputKey, 0, BLOCK_SIZE);
    }

    private void funcC(char number, char[] output) {
        char[] tempI = new char[BLOCK_SIZE];

        //memset( tempI, 0, 15 );

        java.util.Arrays.fill(tempI, (char) 0);
        tempI[BLOCK_SIZE-1] = number;
        funcL(tempI, output);
    }

    public void expandKey(char[] masterKey, char[] keys) {
        char[] C = new char[BLOCK_SIZE];
        char[] temp1 = new char[BLOCK_SIZE];
        char[] temp2 = new char[BLOCK_SIZE];
        char j, i;

        //memcpy(keys, masterKey, 16);
        System.arraycopy(masterKey , 0, keys, 0, BLOCK_SIZE);
        //memcpy(keys + 16, masterKey + 16, 16);
        System.arraycopy(masterKey , 16, keys, BLOCK_SIZE, BLOCK_SIZE); //TODO: 16?

        for(j = 0; j < 4; ++j) {
            //memcpy(temp1, keys + j * 2 * 16, 16);
            System.arraycopy(keys , j * 2 * BLOCK_SIZE, temp1, 0, BLOCK_SIZE);

            //memcpy(temp2, keys + (j * 2 + 1) * 16, 16);
            System.arraycopy(keys , (j * 2 + 1) * BLOCK_SIZE, temp2, 0, BLOCK_SIZE);

            for( i = 1; i < 8; ++i ) {
                funcC((char) (j*8+i), C);
                funcF(temp1, temp2, C, temp1, temp2);
            }

            funcC((char) (j*8+8), C);
            funcF(temp1, temp2, C, temp1, temp2);

            //memcpy(keys + (j * 2 + 2) * 16, temp1, 16);
            System.arraycopy(temp1 , 0, keys, (j * 2 + 2) * BLOCK_SIZE, BLOCK_SIZE);
            //memcpy(keys + (j * 2 + 3) * 16, temp2, 16);
            System.arraycopy(temp2 , 0, keys, (j * 2 + 3) * BLOCK_SIZE, BLOCK_SIZE);
        }
    }

    private  void encrypt(char[] plainText, char[] chipherText) {
        char[] xTemp = new char[BLOCK_SIZE];
        char[] yTemp = new char[BLOCK_SIZE];
        int i;

        //memcpy(xTemp, plainText, 16);
        System.arraycopy(plainText , 0, xTemp, 0, BLOCK_SIZE);

        for(i = 0; i < 9; ++i) {
            char[] tempKeys = new char[BLOCK_SIZE];
            System.arraycopy(workingKey, BLOCK_SIZE*i, tempKeys, 0, BLOCK_SIZE);

            funcLSX(xTemp, tempKeys, yTemp);

            //memcpy(xTemp, yTemp, 16);
            System.arraycopy(yTemp, 0, xTemp, 0, BLOCK_SIZE);
        }

        char[] tempKeys = new char[16];
        System.arraycopy(workingKey, 9*BLOCK_SIZE, tempKeys, 0, BLOCK_SIZE);
        funcX(yTemp, tempKeys, chipherText);
    }



    private void decrypt(char[] chipherText, char[] plainText) {
        char[] xTemp = new char[BLOCK_SIZE];
        char[] yTemp = new char[BLOCK_SIZE];
        int i;

        //memcpy(xTemp, chipherText, 16);
        System.arraycopy(chipherText, 0, xTemp, 0, BLOCK_SIZE);

        for (i = 0; i < 9; ++i) {
            char[] tempKeys = new char[BLOCK_SIZE];
            System.arraycopy(workingKey, (9 - i) * BLOCK_SIZE, tempKeys, 0, BLOCK_SIZE);

            funcReverseLSX(xTemp, tempKeys, yTemp);

            //memcpy(xTemp, yTemp, 16);
            System.arraycopy(yTemp, 0, xTemp, 0, BLOCK_SIZE);
        }
        funcX(yTemp, workingKey, plainText);
    }


    public void init(boolean forEncryption, CipherParameters params) {
        if (params instanceof KeyParameter) {
            workingKey = generateWorkingKey(forEncryption, ((KeyParameter)params).getKey());
        } else if (params != null) {
                throw new IllegalArgumentException("invalid parameter passed to GOST28147 init - " + params.getClass().getName());
            }
    }


    private char[] generateWorkingKey(
            boolean forEncryption,
            byte[]  userKey) {
        this.forEncryption = forEncryption;

        if (userKey.length != 32) {
            throw new IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!");
        }
        char key[] = new char[10*BLOCK_SIZE];
        expandKey(bytesToChars(userKey), key);

        return key;
    }

    public String getAlgorithmName() {
        return "GOST28147-14";
    }

    public int getBlockSize() {
        return BLOCK_SIZE;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (workingKey == null) {
            throw new IllegalStateException("GOST28147 engine not initialised");
        }

        if ((inOff + BLOCK_SIZE) > in.length) {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + BLOCK_SIZE) > out.length) {
            throw new OutputLengthException("output buffer too short");
        }

        GOST28147_14Func(workingKey, in, inOff, out, outOff);

        return BLOCK_SIZE;
    }

    private void GOST28147_14Func(
            char[]   workingKey,
            byte[]  in,
            int     inOff,
            byte[]  out,
            int     outOff) {

        char[] charIn = bytesToChars(in, inOff);
        char[] charOut = new char[BLOCK_SIZE];

        if (this.forEncryption) {
            encrypt(charIn, charOut);
        }
        else { //decrypt
            decrypt(charIn, charOut);
        }

        charsToBytes(charOut, out, outOff);
    }


    private char[] bytesToChars(byte[]  in) {
        char[] answ = new char[in.length];
        for(int i = 0; i < in.length; i++)
            answ[i] = (char)(in[i] & 0xFF);

        return answ;
    }

    private char[] bytesToChars(byte[] in, int off) {
        byte[] tmp = new byte[BLOCK_SIZE];
        System.arraycopy(in, off, tmp, 0, BLOCK_SIZE);

        return bytesToChars(tmp);
    }


    private byte[] charsToBytes(char[] in) {
        byte[] answ = new byte[in.length];
        for(int i = 0; i < in.length; i++)
            answ[i] = (byte)(in[i] & 0xFF);

        return answ;
    }


    private void charsToBytes(char[] in, byte[] out, int OutOff) {
        byte[] tmp = charsToBytes(in);

        System.arraycopy(tmp, 0, out, OutOff, BLOCK_SIZE);
    }


    public void reset() {

    }




    private void testS() {
        char kSData[][] =
        {
            {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00},
            {0xb6, 0x6c, 0xd8, 0x88, 0x7d, 0x38, 0xe8, 0xd7, 0x77, 0x65, 0xae, 0xea, 0x0c, 0x9a, 0x7e, 0xfc},
            {0x55, 0x9d, 0x8d, 0xd7, 0xbd, 0x06, 0xcb, 0xfe, 0x7e, 0x7b, 0x26, 0x25, 0x23, 0x28, 0x0d, 0x39},
            {0x0c, 0x33, 0x22, 0xfe, 0xd5, 0x31, 0xe4, 0x63, 0x0d, 0x80, 0xef, 0x5c, 0x5a, 0x81, 0xc5, 0x0b},
            {0x23, 0xae, 0x65, 0x63, 0x3f, 0x84, 0x2d, 0x29, 0xc5, 0xdf, 0x52, 0x9c, 0x13, 0xf5, 0xac, 0xda}
        };

        char[] tmp = new char[16];

        for(int i = 0; i < 4; ++i)
        {
            funcS(kSData[i], tmp);

            System.out.println("Expected S: ");
            for(char c : tmp)
                System.out.print(" c" +  (int)c);
            System.out.println("");
            System.out.println("Real S: ");
            for(char c : kSData[i+1])
                System.out.print(" c" +  (int)c);
        }
    }

    private void testR() {
        char kRData[][] =
        {
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
            {0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
            {0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x0d, 0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
        };
        char[] tmp = new char[16];

        for(int i =0; i < 4; ++i)
        {
            funcR(kRData[i], tmp);
            System.out.println("");
            System.out.println("Expected R: ");
            for(char c : kRData[i+1])
                System.out.print(" c" +  (int)c);
            System.out.println("");
            System.out.println("Real R: ");
            for(char c : tmp)
                System.out.print(" c" +  (int)c);
        }


    }

    public static void main(String[] args) {
        new  GOST28147_14Engine().testS();
        new  GOST28147_14Engine().testR();

    }
}
