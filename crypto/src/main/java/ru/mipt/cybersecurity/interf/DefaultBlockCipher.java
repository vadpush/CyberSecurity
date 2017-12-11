package ru.mipt.cybersecurity.interf;
import ru.mipt.cybersecurity.util.StringUtils;



public class DefaultBlockCipher extends AbstractSymmetricCipher {

    private static final int DEFAULT_BLOCK_SIZE = 0;
    private static final String TRANSFORMATION_STRING_DELIMITER = "/";
    private static final int DEFAULT_STREAMING_BLOCK_SIZE = 8; //8 bits (1 byte)

    private String modeName;
    private int blockSize; //size in bits (not bytes) - i.e. a blockSize of 8 equals 1 byte. negative or zero value = use system default
    private String paddingSchemeName;

    private String streamingModeName;
    private int streamingBlockSize;
    private String streamingPaddingSchemeName;

    private String transformationString; //cached value - rebuilt whenever any of its constituent parts change
    private String streamingTransformationString; //cached value - rebuilt whenever any of its constituent parts change


    /**
     * Creates a new {@link DefaultBlockCipher} using the specified block cipher {@code algorithmName}.  Per this
     * class's JavaDoc, this constructor also sets the following defaults:
     * <ul>
     * <li>{@code streamingMode} = {@link OperationMode#CBC CBC}</li>
     * <li>{@code streamingPaddingScheme} = {@link PaddingScheme#NONE none}</li>
     * <li>{@code streamingBlockSize} = 8</li>
     * </ul>
     * All other attributes are null/unset, indicating the JCA Provider defaults will be used.
     *
     * @param algorithmName the block cipher algorithm to use when encrypting and decrypting
     */
    public DefaultBlockCipher(String algorithmName) {
        super(algorithmName);

        this.modeName = OperationMode.CBC.name();
        this.paddingSchemeName = PaddingScheme.PKCS5.getTransformationName();
        this.blockSize = DEFAULT_BLOCK_SIZE; //0 = use the JCA provider's default

        this.streamingModeName = OperationMode.CBC.name();
        this.streamingPaddingSchemeName = PaddingScheme.PKCS5.getTransformationName();
        this.streamingBlockSize = DEFAULT_STREAMING_BLOCK_SIZE;
    }

    /**
     * Returns the cipher operation mode name (as a String) to be used when constructing
     * {@link javax.crypto.Cipher Cipher} transformation string or {@code null} if the JCA Provider default mode for
     * the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #getStreamingModeName() streamingModeName} attribute is used when the block cipher is used for
     * streaming operations.
     * <p/>
     * The default value is {@code null} to retain the JCA Provider default.
     *
     * @return the cipher operation mode name (as a String) to be used when constructing the
     *         {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA Provider default
     *         mode for the specified {@link #getAlgorithmName() algorithm} should be used.
     */
    public String getModeName() {
        return modeName;
    }

    /**
     * Sets the cipher operation mode name to be used when constructing the
     * {@link javax.crypto.Cipher Cipher} transformation string.  A {@code null} value indicates that the JCA Provider
     * default mode for the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #getStreamingModeName() streamingModeName} attribute is used when the block cipher is used for
     * streaming operations.
     * <p/>
     * The default value is {@code null} to retain the JCA Provider default.
     * <p/>
     * <b>NOTE:</b> most standard mode names are represented by the {@link OperationMode OperationMode} enum.  That enum
     * should be used with the {@link #setMode mode} attribute when possible to retain type-safety and reduce the
     * possibility of errors.  This method is better used if the {@link OperationMode} enum does not represent the
     * necessary mode.
     *
     * @param modeName the cipher operation mode name to be used when constructing
     *                 {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA Provider
     *                 default mode for the specified {@link #getAlgorithmName() algorithm} should be used.
     * @see #setMode
     */
    public void setModeName(String modeName) {
        this.modeName = modeName;
        //clear out the transformation string so the next invocation will rebuild it with the new mode:
        this.transformationString = null;
    }

    /**
     * Sets the cipher operation mode of operation to be used when constructing the
     * {@link javax.crypto.Cipher Cipher} transformation string.  A {@code null} value indicates that the JCA Provider
     * default mode for the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #setStreamingMode streamingMode} attribute is used when the block cipher is used for
     * streaming operations.
     * <p/>
     * If the {@link OperationMode} enum cannot represent your desired mode, you can set the name explicitly
     * via the {@link #setModeName modeName} attribute directly.  However, because {@link OperationMode} represents all
     * standard JDK mode names already, ensure that your underlying JCA Provider supports the non-standard name first.
     *
     * @param mode the cipher operation mode to be used when constructing
     *             {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA Provider
     *             default mode for the specified {@link #getAlgorithmName() algorithm} should be used.
     */
    public void setMode(OperationMode mode) {
        setModeName(mode.name());
    }

    /**
     * Returns the cipher algorithm padding scheme name (as a String) to be used when constructing
     * {@link javax.crypto.Cipher Cipher} transformation string or {@code null} if the JCA Provider default mode for
     * the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #getStreamingPaddingSchemeName() streamingPaddingSchemeName} attribute is used when the block cipher is
     * used for streaming operations.
     * <p/>
     * The default value is {@code null} to retain the JCA Provider default.
     *
     * @return the padding scheme name (as a String) to be used when constructing the
     *         {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA Provider default
     *         padding scheme for the specified {@link #getAlgorithmName() algorithm} should be used.
     */
    public String getPaddingSchemeName() {
        return paddingSchemeName;
    }

    /**
     * Sets the padding scheme name to be used when constructing the
     * {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA Provider default mode for
     * the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #getStreamingPaddingSchemeName() streamingPaddingSchemeName} attribute is used when the block cipher is
     * used for streaming operations.
     * <p/>
     * The default value is {@code null} to retain the JCA Provider default.
     * <p/>
     * <b>NOTE:</b> most standard padding schemes are represented by the {@link PaddingScheme PaddingScheme} enum.
     * That enum should be used with the {@link #setPaddingScheme paddingScheme} attribute when possible to retain
     * type-safety and reduce the possibility of errors.  Calling this method however is suitable if the
     * {@code PaddingScheme} enum does not represent the desired scheme.
     *
     * @param paddingSchemeName the padding scheme name to be used when constructing
     *                          {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA
     *                          Provider default padding scheme for the specified {@link #getAlgorithmName() algorithm}
     *                          should be used.
     * @see #setPaddingScheme
     */
    public void setPaddingSchemeName(String paddingSchemeName) {
        this.paddingSchemeName = paddingSchemeName;
        //clear out the transformation string so the next invocation will rebuild it with the new padding scheme:
        this.transformationString = null;
    }

    /**
     * Sets the padding scheme to be used when constructing the
     * {@link javax.crypto.Cipher Cipher} transformation string. A {@code null} value indicates that the JCA Provider
     * default padding scheme for the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #setStreamingPaddingScheme streamingPaddingScheme} attribute is used when the block cipher is used for
     * streaming operations.
     * <p/>
     * If the {@link PaddingScheme PaddingScheme} enum does represent your desired scheme, you can set the name explicitly
     * via the {@link #setPaddingSchemeName paddingSchemeName} attribute directly.  However, because
     * {@code PaddingScheme} represents all standard JDK scheme names already, ensure that your underlying JCA Provider
     * supports the non-standard name first.
     *
     * @param paddingScheme the padding scheme to be used when constructing
     *                      {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA Provider
     *                      default padding scheme for the specified {@link #getAlgorithmName() algorithm} should be used.
     */
    public void setPaddingScheme(PaddingScheme paddingScheme) {
        setPaddingSchemeName(paddingScheme.getTransformationName());
    }

    /**
     * Returns the block cipher's block size to be used when constructing
     * {@link javax.crypto.Cipher Cipher} transformation string or {@code 0} if the JCA Provider default block size
     * for the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #getStreamingBlockSize() streamingBlockSize} attribute is used when the block cipher is used for
     * streaming operations.
     * <p/>
     * The default value is {@code 0} which retains the JCA Provider default.
     *
     * @return the block cipher block size to be used when constructing the
     *         {@link javax.crypto.Cipher Cipher} transformation string, or {@code 0} if the JCA Provider default
     *         block size for the specified {@link #getAlgorithmName() algorithm} should be used.
     */
    public int getBlockSize() {
        return blockSize;
    }

    /**
     * Sets the block cipher's block size to be used when constructing
     * {@link javax.crypto.Cipher Cipher} transformation string.  {@code 0} indicates that the JCA Provider default
     * block size for the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #getStreamingBlockSize() streamingBlockSize} attribute is used when the block cipher is used for
     * streaming operations.
     * <p/>
     * The default value is {@code 0} which retains the JCA Provider default.
     * <p/>
     * <b>NOTE:</b> block cipher block sizes are very algorithm-specific.  If you change this value, ensure that it
     * will work with the specified {@link #getAlgorithmName() algorithm}.
     *
     * @param blockSize the block cipher block size to be used when constructing the
     *                  {@link javax.crypto.Cipher Cipher} transformation string, or {@code 0} if the JCA Provider
     *                  default block size for the specified {@link #getAlgorithmName() algorithm} should be used.
     */
    public void setBlockSize(int blockSize) {
        this.blockSize = Math.max(DEFAULT_BLOCK_SIZE, blockSize);
        //clear out the transformation string so the next invocation will rebuild it with the new block size:
        this.transformationString = null;
    }

    /**
     * Same purpose as the {@link #getModeName modeName} attribute, but is used instead only for for streaming
     * operations ({@link #encrypt(java.io.InputStream, java.io.OutputStream, byte[])} and
     * {@link #decrypt(java.io.InputStream, java.io.OutputStream, byte[])}).
     * <p/>
     * Note that unlike the {@link #getModeName modeName} attribute, the default value of this attribute is not
     * {@code null} - it is {@link OperationMode#CBC CBC} for reasons described in the class-level JavaDoc in the
     * {@code Streaming} section.
     *
     * @return the transformation string mode name to be used for streaming operations only.
     */
    public String getStreamingModeName() {
        return streamingModeName;
    }

    private boolean isModeStreamingCompatible(String modeName) {
        return modeName != null &&
                !modeName.equalsIgnoreCase(OperationMode.ECB.name()) &&
                !modeName.equalsIgnoreCase(OperationMode.NONE.name());
    }

    /**
     * Sets the transformation string mode name to be used for streaming operations only.  The default value is
     * {@link OperationMode#CBC CBC} for reasons described in the class-level JavaDoc in the {@code Streaming} section.
     *
     * @param streamingModeName transformation string mode name to be used for streaming operations only
     */
    public void setStreamingModeName(String streamingModeName) {
        if (!isModeStreamingCompatible(streamingModeName)) {
            String msg = "mode [" + streamingModeName + "] is not a valid operation mode for block cipher streaming.";
            throw new IllegalArgumentException(msg);
        }
        this.streamingModeName = streamingModeName;
        //clear out the streaming transformation string so the next invocation will rebuild it with the new mode:
        this.streamingTransformationString = null;
    }

    /**
     * Sets the transformation string mode to be used for streaming operations only.  The default value is
     * {@link OperationMode#CBC CBC} for reasons described in the class-level JavaDoc in the {@code Streaming} section.
     *
     * @param mode the transformation string mode to be used for streaming operations only
     */
    public void setStreamingMode(OperationMode mode) {
        setStreamingModeName(mode.name());
    }

    public String getStreamingPaddingSchemeName() {
        return streamingPaddingSchemeName;
    }

    public void setStreamingPaddingSchemeName(String streamingPaddingSchemeName) {
        this.streamingPaddingSchemeName = streamingPaddingSchemeName;
        //clear out the streaming transformation string so the next invocation will rebuild it with the new scheme:
        this.streamingTransformationString = null;
    }

    public void setStreamingPaddingScheme(PaddingScheme scheme) {
        setStreamingPaddingSchemeName(scheme.getTransformationName());
    }

    public int getStreamingBlockSize() {
        return streamingBlockSize;
    }

    public void setStreamingBlockSize(int streamingBlockSize) {
        this.streamingBlockSize = Math.max(DEFAULT_BLOCK_SIZE, streamingBlockSize);
        //clear out the streaming transformation string so the next invocation will rebuild it with the new block size:
        this.streamingTransformationString = null;
    }

    /**
     * Returns the transformation string to use with the {@link javax.crypto.Cipher#getInstance} call.  If
     * {@code streaming} is {@code true}, a block-cipher transformation string compatible with streaming operations will
     * be constructed and cached for re-use later (see the class-level JavaDoc for more on using block ciphers
     * for streaming).  If {@code streaming} is {@code false} a normal block-cipher transformation string will
     * be constructed and cached for later re-use.
     *
     * @param streaming if the transformation string is going to be used for a Cipher performing stream-based encryption or not.
     * @return the transformation string
     */
    protected String getTransformationString(boolean streaming) {
        if (streaming) {
            if (this.streamingTransformationString == null) {
                this.streamingTransformationString = buildStreamingTransformationString();
            }
            return this.streamingTransformationString;
        } else {
            if (this.transformationString == null) {
                this.transformationString = buildTransformationString();
            }
            return this.transformationString;
        }
    }

    private String buildTransformationString() {
        return buildTransformationString(getModeName(), getPaddingSchemeName(), getBlockSize());
    }

    private String buildStreamingTransformationString() {
        return buildTransformationString(getStreamingModeName(), getStreamingPaddingSchemeName(), 0);
    }

    private String buildTransformationString(String modeName, String paddingSchemeName, int blockSize) {
        StringBuilder sb = new StringBuilder(getAlgorithmName());
        if (StringUtils.hasText(modeName)) {
            sb.append(TRANSFORMATION_STRING_DELIMITER).append(modeName);
        }
        if (blockSize > 0) {
            sb.append(blockSize);
        }
        if (StringUtils.hasText(paddingSchemeName)) {
            sb.append(TRANSFORMATION_STRING_DELIMITER).append(paddingSchemeName);
        }
        return sb.toString();
    }

    /**
     * Returns {@code true} if the specified cipher operation mode name supports initialization vectors,
     * {@code false} otherwise.
     *
     * @param modeName the raw text name of the mode of operation
     * @return {@code true} if the specified cipher operation mode name supports initialization vectors,
     *         {@code false} otherwise.
     */
    private boolean isModeInitializationVectorCompatible(String modeName) {
        return modeName != null &&
                !modeName.equalsIgnoreCase(OperationMode.ECB.name()) &&
                !modeName.equalsIgnoreCase(OperationMode.NONE.name());
    }

    /**
     * Overrides the parent implementation to ensure initialization vectors are always generated if streaming is
     * enabled (block ciphers <em>must</em> use initialization vectors if they are to be used as a stream cipher).  If
     * not being used as a stream cipher, then the value is computed based on whether or not the currently configured
     * {@link #getModeName modeName} is compatible with initialization vectors as well as the result of the configured
     * {@link #setGenerateInitializationVectors(boolean) generateInitializationVectors} value.
     *
     * @param streaming whether or not streaming is being performed
     * @return {@code true} if streaming or a value computed based on if the currently configured mode is compatible
     *         with initialization vectors.
     */
    @Override
    protected boolean isGenerateInitializationVectors(boolean streaming) {
        return streaming || super.isGenerateInitializationVectors() && isModeInitializationVectorCompatible(getModeName());
    }

    @Override
    protected byte[] generateInitializationVector(boolean streaming) {
        if (streaming) {
            String streamingModeName = getStreamingModeName();
            if (!isModeInitializationVectorCompatible(streamingModeName)) {
                String msg = "streamingMode attribute value [" + streamingModeName + "] does not support " +
                        "Initialization Vectors.  Ensure the streamingMode value represents an operation mode " +
                        "that is compatible with initialization vectors.";
                throw new IllegalStateException(msg);
            }
        } else {
            String modeName = getModeName();
            if (!isModeInitializationVectorCompatible(modeName)) {
                String msg = "mode attribute value [" + modeName + "] does not support " +
                        "Initialization Vectors.  Ensure the mode value represents an operation mode " +
                        "that is compatible with initialization vectors.";
                throw new IllegalStateException(msg);
            }
        }
        return super.generateInitializationVector(streaming);
    }

}
