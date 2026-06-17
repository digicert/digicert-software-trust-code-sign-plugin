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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import hudson.model.TaskListener;
import hudson.util.Secret;

/**
 * Shared agent-side behaviour for installing Software Trust Manager tooling and
 * performing simplified signing. OS specific subclasses ({@link Windows},
 * {@link Linux}, {@link MacOS}) provide the platform details while this class
 * centralises secure command execution, integrity-checked downloads, artifact
 * caching and the {@code smctl} simple-signing flow.
 */
public abstract class BaseAgent {

    protected final TaskListener listener;
    protected final String SM_HOST;
    protected final Secret SM_API_KEY;
    protected final String SM_CLIENT_CERT_FILE;
    protected final Secret SM_CLIENT_CERT_PASSWORD;
    protected final String pathVar;
    protected final SigningConfig config;

    protected String dir;
    protected final String baseDir;
    /** Tool directory to be added to PATH for subsequent pipeline steps. */
    protected String exportedPath;
    /**
     * True once installation/configuration (setup) has completed successfully.
     * The signing exit code is tracked separately, so a non-zero result from
     * {@code smctl sign} (e.g. some files in a bulk directory are unsupported)
     * is not misreported as a setup failure.
     */
    protected boolean setupSucceeded = false;

    protected BaseAgent(TaskListener listener, String SM_HOST, Secret SM_API_KEY, String SM_CLIENT_CERT_FILE,
            Secret SM_CLIENT_CERT_PASSWORD, String pathVar, SigningConfig config, String workspace) {
        this.listener = listener;
        this.SM_HOST = SM_HOST;
        this.SM_API_KEY = SM_API_KEY;
        this.SM_CLIENT_CERT_FILE = SM_CLIENT_CERT_FILE;
        this.SM_CLIENT_CERT_PASSWORD = SM_CLIENT_CERT_PASSWORD;
        this.pathVar = pathVar;
        this.config = config;
        this.baseDir = workspace;
        this.dir = workspace;
    }

    /** Entry point invoked by {@link AgentInfo}. */
    public abstract Integer call(String os) throws IOException;

    // ------------------------------------------------------------------
    // Command execution (no shell — arguments are passed discretely to
    // ProcessBuilder, preventing shell metacharacter / command injection).
    // ------------------------------------------------------------------

    public Integer executeCommand(List<String> command) {
        return executeCommand(command, false);
    }

    public Integer executeCommand(List<String> command, boolean suppressOutput) {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            Map<String, String> env = processBuilder.environment();
            if (SM_API_KEY != null)
                env.put(Constants.API_KEY_ID, SM_API_KEY.getPlainText());
            if (SM_CLIENT_CERT_PASSWORD != null)
                env.put(Constants.CLIENT_CERT_PASSWORD_ID, SM_CLIENT_CERT_PASSWORD.getPlainText());
            if (SM_CLIENT_CERT_FILE != null)
                env.put(Constants.CLIENT_CERT_FILE_ID, SM_CLIENT_CERT_FILE);
            if (SM_HOST != null)
                env.put(Constants.HOST_ID, SM_HOST);
            addToolPathToEnv(env);
            processBuilder.directory(new File(dir));
            if (suppressOutput) {
                processBuilder.redirectOutput(ProcessBuilder.Redirect.DISCARD);
                processBuilder.redirectError(ProcessBuilder.Redirect.DISCARD);
                Process process = processBuilder.start();
                return process.waitFor();
            }
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    this.listener.getLogger().println(line);
                }
            }
            return process.waitFor();
        } catch (IOException e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return 1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            e.printStackTrace(this.listener.error(e.getMessage()));
            return 1;
        }
    }

    /** Adds the OS specific tool directory to the PATH of a child process. */
    protected abstract void addToolPathToEnv(Map<String, String> env);

    // ------------------------------------------------------------------
    // Jenkins environment / file helpers
    // ------------------------------------------------------------------

    public Integer createFile(String path, String str) {
        File file = new File(path);
        try {
            file.createNewFile();
            try (FileOutputStream fos = new FileOutputStream(file.getCanonicalPath(), false)) {
                fos.write(str.getBytes(StandardCharsets.UTF_8));
            }
            return 0;
        } catch (IOException e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return 1;
        }
    }

    // ------------------------------------------------------------------
    // CDN URL handling
    // ------------------------------------------------------------------

    /**
     * Validates the configured CDN and returns the artifact download URL.
     * Only HTTPS is permitted, mitigating man-in-the-middle attacks.
     *
     * @return the full download URL, or {@code null} when the CDN is invalid.
     */
    protected String cdnUrl(String artifact) {
        String cdn = config.getCdn();
        if (cdn == null || !cdn.startsWith("https://")) {
            this.listener.error("Invalid digicertCdn URL: '" + cdn
                    + "'. The CDN URL must use HTTPS to prevent man-in-the-middle attacks.");
            return null;
        }
        return cdn.replaceAll("/+$", "") + "/" + artifact;
    }

    // ------------------------------------------------------------------
    // Integrity checked, cache aware downloads
    // ------------------------------------------------------------------

    /**
     * Downloads {@code url} to {@code destFile} and verifies its SHA-256.
     * The expected checksum is resolved by first attempting to fetch a sibling
     * {@code <url>.sha256} file (as published on the DigiCert CDN and on Maven
     * Central) and, failing that, falling back to an optional value in
     * {@code config.properties} keyed by {@code configChecksumKey}. When no
     * checksum can be resolved a warning is logged and verification is skipped.
     *
     * <p>Verified artifacts are cached under the user's home directory keyed by
     * their checksum so subsequent builds can avoid re-downloading them.</p>
     *
     * @return 0 on success, non-zero on download failure or checksum mismatch.
     */
    protected Integer downloadAndVerify(String toolName, String url, File destFile, String configChecksumKey) {
        String expected = resolveExpectedChecksum(url, configChecksumKey);

        File cacheFile = null;
        if (expected != null) {
            cacheFile = new File(cacheRoot(), expected + "_" + destFile.getName());
            if (cacheFile.isFile() && expected.equalsIgnoreCase(computeSha256(cacheFile))) {
                this.listener.getLogger().println("\n" + toolName + " found in local cache; reusing "
                        + cacheFile.getAbsolutePath() + "\n");
                try {
                    Files.copy(cacheFile.toPath(), destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    return 0;
                } catch (IOException e) {
                    this.listener.getLogger().println("Failed to copy cached artifact, re-downloading: "
                            + e.getMessage());
                }
            }
        }

        this.listener.getLogger().println("\nDownloading " + toolName + " from: " + url);
        destFile.getParentFile().mkdirs();
        Integer rc = executeCommand(Arrays.asList("curl", "-fsSL", url, "-o", destFile.getAbsolutePath()));
        if (rc != 0) {
            this.listener.error(toolName + " failed to download from " + url);
            return rc;
        }

        if (!verifyChecksum(destFile, expected)) {
            return 1;
        }

        if (expected != null && cacheFile != null) {
            try {
                File cacheDir = cacheRoot();
                if (cacheDir != null) {
                    Files.copy(destFile.toPath(), cacheFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (IOException e) {
                this.listener.getLogger().println("Could not cache " + toolName + ": " + e.getMessage());
            }
        }
        return 0;
    }

    /** Attempts to read a sibling {@code .sha256} file, then the config fallback. */
    protected String resolveExpectedChecksum(String url, String configChecksumKey) {
        String fromSidecar = fetchSiblingChecksum(url);
        if (fromSidecar != null) {
            return fromSidecar;
        }
        String fromConfig = getChecksumFromConfig(configChecksumKey);
        if (fromConfig != null && !fromConfig.trim().isEmpty()) {
            return fromConfig.trim().toLowerCase();
        }
        return null;
    }

    private String fetchSiblingChecksum(String url) {
        File tmp = null;
        try {
            tmp = File.createTempFile("stm-checksum", ".sha256");
            Integer rc = executeCommand(
                    Arrays.asList("curl", "-fsSL", url + ".sha256", "-o", tmp.getAbsolutePath()), true);
            if (rc != 0 || tmp.length() == 0) {
                return null;
            }
            String content = new String(Files.readAllBytes(tmp.toPath()), StandardCharsets.UTF_8).trim();
            if (content.isEmpty()) {
                return null;
            }
            String token = content.split("\\s+")[0].trim().toLowerCase();
            return token.matches("[a-f0-9]{64}") ? token : null;
        } catch (IOException e) {
            return null;
        } finally {
            if (tmp != null) {
                tmp.delete();
            }
        }
    }

    protected String getChecksumFromConfig(String key) {
        if (key == null) {
            return null;
        }
        try (InputStream input = BaseAgent.class.getResourceAsStream("config.properties")) {
            Properties prop = new Properties();
            prop.load(input);
            return prop.getProperty(key);
        } catch (IOException e) {
            return null;
        }
    }

    protected String getConfigProperty(String key) {
        try (InputStream input = BaseAgent.class.getResourceAsStream("config.properties")) {
            Properties prop = new Properties();
            prop.load(input);
            return prop.getProperty(key);
        } catch (IOException e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return null;
        }
    }

    protected boolean verifyChecksum(File file, String expectedSha256) {
        if (expectedSha256 == null || expectedSha256.trim().isEmpty()) {
            this.listener.getLogger().println("\nWARNING: No SHA-256 checksum available for " + file.getName()
                    + "; skipping integrity verification. This reduces protection against supply chain attacks.\n");
            return true;
        }
        String actual = computeSha256(file);
        if (actual != null && actual.equalsIgnoreCase(expectedSha256.trim())) {
            this.listener.getLogger().println("\nChecksum verified for " + file.getName() + "\n");
            return true;
        }
        this.listener.error("SECURITY ERROR: SHA-256 checksum mismatch for " + file.getName() + ". Expected "
                + expectedSha256.trim() + " but computed " + actual + ". The file may have been tampered with;"
                + " aborting.");
        file.delete();
        return false;
    }

    protected String computeSha256(File file) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(Files.readAllBytes(file.toPath()));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return null;
        }
    }

    /** @return the cache directory (created on demand) or {@code null} if unavailable. */
    protected File cacheRoot() {
        try {
            File root = new File(System.getProperty("user.home"), ".digicert-stm-cache");
            if (root.isDirectory() || root.mkdirs()) {
                return root;
            }
        } catch (Exception e) {
            this.listener.getLogger().println("Could not initialise tool cache: " + e.getMessage());
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Simplified signing via smctl
    // ------------------------------------------------------------------

    /**
     * Runs {@code smctl sign --simple} using the supplied executable and the
     * options captured in {@link SigningConfig}.
     */
    protected Integer simpleSign(String smctlExecutable) {
        if (!config.isSigningRequested()) {
            return 0;
        }
        this.listener.getLogger().println("\nSigning '" + config.getInput() + "' with keypair alias '"
                + config.getKeypairAlias() + "'\n");

        List<String> args = new ArrayList<>();
        args.add(smctlExecutable);
        args.add("sign");
        args.add("--simple");
        args.add("--input");
        args.add(config.getInput());
        args.add("--keypair-alias");
        args.add(config.getKeypairAlias());
        if (!config.isTimestamp()) {
            args.add("--timestamp=false");
        }
        if (SigningConfig.isValid(config.getDigestAlg())) {
            args.add("--digalg");
            args.add(config.getDigestAlg().trim());
        }
        if (!config.isZeroExitCodeOnFailure()) {
            args.add("--exit-non-zero-on-fail");
        }
        if (config.isFailFast()) {
            args.add("--failfast");
        }
        if (config.isUnsigned()) {
            args.add("--unsigned");
        }
        if (config.isBulkSign()) {
            args.add("--bulk");
        }

        Integer rc = executeCommand(args);
        if (rc == 0) {
            this.listener.getLogger().println("\nSigning completed successfully\n");
        } else {
            this.listener.error("Signing failed with exit code " + rc);
        }
        return rc;
    }
}
