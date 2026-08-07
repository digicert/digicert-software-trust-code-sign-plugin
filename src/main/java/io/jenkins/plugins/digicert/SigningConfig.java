//The MIT License
//
//Copyright 2023
//
//Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package io.jenkins.plugins.digicert;

import java.io.Serializable;

/**
 * Serializable holder for the optional configuration supplied to the
 * {@code SoftwareTrustManagerSetup} pipeline step. Instances are created on the
 * Jenkins controller and shipped to the agent as part of {@link AgentInfo}, so
 * every field must be serializable.
 *
 * <p>When neither {@code input} nor {@code keypairAlias} are provided the step
 * behaves exactly like earlier releases: it only installs and configures the
 * signing tools. When both are provided the step additionally performs a
 * simplified {@code smctl} signing in the same invocation.</p>
 */
public class SigningConfig implements Serializable {

    private static final long serialVersionUID = 1L;

    /** Default DigiCert CDN that hosts the Software Trust Manager client tools. */
    public static final String DEFAULT_CDN = "https://pki-downloads.digicert.com/stm/latest";

    private final String cdn;
    private final String input;
    private final String keypairAlias;
    private final boolean simpleSigningMode;
    private final boolean timestamp;
    private final String digestAlg;
    private final boolean failFast;
    private final boolean unsigned;
    private final boolean bulkSign;
    private final boolean zeroExitCodeOnFailure;

    public SigningConfig(String cdn, String input, String keypairAlias, boolean simpleSigningMode,
            boolean timestamp, String digestAlg, boolean failFast, boolean unsigned, boolean bulkSign,
            boolean zeroExitCodeOnFailure) {
        this.cdn = isValid(cdn) ? cdn.trim() : DEFAULT_CDN;
        this.input = input;
        this.keypairAlias = keypairAlias;
        this.simpleSigningMode = simpleSigningMode;
        this.timestamp = timestamp;
        this.digestAlg = digestAlg;
        this.failFast = failFast;
        this.unsigned = unsigned;
        this.bulkSign = bulkSign;
        this.zeroExitCodeOnFailure = zeroExitCodeOnFailure;
    }

    /** @return the CDN base URL (no trailing slash guaranteed by callers). */
    public String getCdn() {
        return cdn;
    }

    public String getInput() {
        return input;
    }

    public String getKeypairAlias() {
        return keypairAlias;
    }

    public boolean isSimpleSigningMode() {
        return simpleSigningMode;
    }

    public boolean isTimestamp() {
        return timestamp;
    }

    public String getDigestAlg() {
        return digestAlg;
    }

    public boolean isFailFast() {
        return failFast;
    }

    public boolean isUnsigned() {
        return unsigned;
    }

    public boolean isBulkSign() {
        return bulkSign;
    }

    public boolean isZeroExitCodeOnFailure() {
        return zeroExitCodeOnFailure;
    }

    /** @return true when enough information was supplied to perform signing. */
    public boolean isSigningRequested() {
        return isValid(input) && isValid(keypairAlias);
    }

    static boolean isValid(String value) {
        return value != null && !value.trim().isEmpty();
    }
}
