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

import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Map;

import hudson.model.TaskListener;
import hudson.util.Secret;

/**
 * macOS agent. Software Trust Manager ships its macOS tooling inside DMG and
 * ZIP archives on the CDN, so this class downloads and verifies each artifact,
 * mounts / extracts it, and installs the binaries / libraries into the
 * workspace. Behaviour mirrors {@link Linux}: a {@code simple-signing} mode
 * only installs {@code smctl}, while the full setup additionally installs
 * {@code smpkcs11}, {@code smctk}, {@code ssm-scd}, writes the PKCS#11
 * configuration file and provisions {@code jsign} / {@code jarsigner}.
 */
public class MacOS extends BaseAgent {

    // --- smctl (smctl-mac-x64.dmg -> smctl-mac-x64) ---
    private static final String SMCTL_DMG_ARTIFACT = "smctl-mac-x64.dmg";
    private static final String SMCTL_BINARY_IN_DMG = "smctl-mac-x64";
    private static final String SMCTL_LOCAL_NAME = "smctl";

    // --- smpkcs11 (smpkcs11.dylib.dmg -> smpkcs11.dylib) ---
    private static final String SMPKCS11_DMG_ARTIFACT = "smpkcs11.dylib.dmg";
    private static final String SMPKCS11_LIB_NAME = "smpkcs11.dylib";

    // --- smctk (DigiCert SSM Signing Clients.zip) ---
    // The on-CDN filename contains spaces and must be URL-encoded for HTTP.
    private static final String SMCTK_ZIP_ARTIFACT = "DigiCert%20SSM%20Signing%20Clients.zip";
    private static final String SMCTK_LOCAL_NAME = "smctk.zip";

    // --- ssm-scd (ssm-scd-x64.dmg -> ssm-scd-x64) ---
    private static final String SCD_DMG_ARTIFACT = "ssm-scd-x64.dmg";
    private static final String SCD_BINARY_IN_DMG = "ssm-scd-x64";
    private static final String SCD_LOCAL_NAME = "ssm-scd";

    /** Directory that should be placed on the PATH for child processes. */
    private String installDir;

    public MacOS(TaskListener listener, String SM_HOST, Secret SM_API_KEY, String SM_CLIENT_CERT_FILE,
            Secret SM_CLIENT_CERT_PASSWORD, String pathVar, SigningConfig config, String workspace) {
        super(listener, SM_HOST, SM_API_KEY, SM_CLIENT_CERT_FILE, SM_CLIENT_CERT_PASSWORD, pathVar, config, workspace);
        this.installDir = workspace;
    }

    @Override
    protected void addToolPathToEnv(Map<String, String> env) {
        String existing = System.getenv("PATH");
        env.put("PATH", (existing == null ? "" : existing) + ":" + installDir);
    }

    @Override
    public Integer call(String os) {
        if (config.isSimpleSigningMode()) {
            return simpleSigningSetup(os);
        }
        return fullSetup(os);
    }

    // ------------------------------------------------------------------
    // Simple signing mode: only smctl is downloaded.
    // ------------------------------------------------------------------

    private Integer simpleSigningSetup(String os) {
        this.listener.getLogger().println("\nAgent type: " + os + " (simple signing mode)");
        installDir = baseDir;
        File smctl = installSmctl();
        if (smctl == null) {
            return 1;
        }
        this.exportedPath = this.pathVar + ":" + installDir;
        this.listener.getLogger().println("\nsmctl successfully installed\n");
        this.setupSucceeded = true;
        return simpleSign(smctl.getAbsolutePath());
    }

    // ------------------------------------------------------------------
    // Full setup: smctl + smpkcs11 + smctk + ssm-scd + PKCS#11 config + jsign.
    // ------------------------------------------------------------------

    private Integer fullSetup(String os) {
        this.listener.getLogger().println("\nAgent type: " + os);
        installDir = baseDir;
        dir = installDir;

        File smctl = installSmctl();
        if (smctl == null) {
            this.listener.getLogger().println("\nSMCTL Installation Failed\n");
            return 1;
        }
        this.listener.getLogger().println("\nSMCTL Installation Complete\n");

        File smpkcs11 = installSmpkcs11();
        if (smpkcs11 == null) {
            this.listener.getLogger().println("\nsmpkcs11 Installation Failed\n");
            return 1;
        }
        this.listener.getLogger().println("\nsmpkcs11 Installation Complete\n");

        // smctk (signing clients) and ssm-scd are auxiliary; failures are logged
        // but do not abort setup -- smctl-based signing remains usable.
        if (installSmctk() != 0) {
            this.listener.getLogger().println("\nsmctk installation failed (continuing)\n");
        } else {
            this.listener.getLogger().println("\nsmctk Installation Complete\n");
        }

        if (installScd() == null) {
            this.listener.getLogger().println("\nssm-scd installation failed (continuing)\n");
        } else {
            this.listener.getLogger().println("\nssm-scd Installation Complete\n");
        }

        this.listener.getLogger().println("\nCreating PKCS11 Config File\n");
        String str = "name=signingmanager\n" +
                "library=" + installDir + "/" + SMPKCS11_LIB_NAME + "\n" +
                "slotListIndex=0\n";
        String configPath = installDir + File.separator + "pkcs11properties.cfg";
        Integer rc = createFile(configPath, str);
        if (rc != 0) {
            this.listener.getLogger().println("\nFailed to create PKCS11 config file\n");
            return rc;
        }
        this.listener.getLogger()
                .println("\nPKCS11 config file successfully created at location: " + configPath + "\n");

        rc = signing();
        if (rc != 0) {
            return rc;
        }

        this.setupSucceeded = true;
        return simpleSign(smctl.getAbsolutePath());
    }

    // ------------------------------------------------------------------
    // Tool installers
    // ------------------------------------------------------------------

    /**
     * Downloads, verifies and extracts {@code smctl} from the CDN-hosted DMG.
     *
     * @return the smctl executable, or {@code null} on failure.
     */
    private File installSmctl() {
        String url = cdnUrl(SMCTL_DMG_ARTIFACT);
        if (url == null) {
            return null;
        }
        File dmg = new File(baseDir, SMCTL_DMG_ARTIFACT);
        if (downloadAndVerify(SMCTL_DMG_ARTIFACT, url, dmg, "smctlMacSha256") != 0) {
            return null;
        }
        File smctl = new File(installDir, SMCTL_LOCAL_NAME);
        if (!mountDmgAndCopy(dmg, new String[]{SMCTL_BINARY_IN_DMG, SMCTL_LOCAL_NAME}, smctl)) {
            return null;
        }
        if (!smctl.setExecutable(true, false)) {
            this.listener.error("Failed to mark smctl as executable");
            return null;
        }
        return smctl;
    }

    /**
     * Downloads, verifies and extracts {@code smpkcs11.dylib} from the
     * CDN-hosted DMG into the install directory.
     *
     * @return the dylib file, or {@code null} on failure.
     */
    private File installSmpkcs11() {
        String url = cdnUrl(SMPKCS11_DMG_ARTIFACT);
        if (url == null) {
            return null;
        }
        File dmg = new File(baseDir, SMPKCS11_DMG_ARTIFACT);
        if (downloadAndVerify(SMPKCS11_DMG_ARTIFACT, url, dmg, "smpkcs11MacSha256") != 0) {
            return null;
        }
        File dylib = new File(installDir, SMPKCS11_LIB_NAME);
        if (!mountDmgAndCopy(dmg, new String[]{SMPKCS11_LIB_NAME}, dylib)) {
            return null;
        }
        return dylib;
    }

    /**
     * Downloads, verifies and unpacks the DigiCert SSM Signing Clients
     * ({@code smctk}) ZIP into the install directory.
     *
     * @return 0 on success, non-zero on failure.
     */
    private Integer installSmctk() {
        String url = cdnUrl(SMCTK_ZIP_ARTIFACT);
        if (url == null) {
            return 1;
        }
        File zip = new File(baseDir, SMCTK_LOCAL_NAME);
        if (downloadAndVerify("smctk", url, zip, "smctkMacSha256") != 0) {
            return 1;
        }
        Integer rc = executeCommand(Arrays.asList("unzip", "-o", "-q",
                zip.getAbsolutePath(), "-d", installDir), true);
        if (rc != 0) {
            this.listener.error("Failed to unzip " + SMCTK_LOCAL_NAME);
            return rc;
        }
        return 0;
    }

    /**
     * Downloads, verifies and extracts the {@code ssm-scd} smart-card daemon
     * from the CDN-hosted DMG.
     *
     * @return the ssm-scd executable, or {@code null} on failure.
     */
    private File installScd() {
        String url = cdnUrl(SCD_DMG_ARTIFACT);
        if (url == null) {
            return null;
        }
        File dmg = new File(baseDir, SCD_DMG_ARTIFACT);
        if (downloadAndVerify(SCD_DMG_ARTIFACT, url, dmg, "scdMacSha256") != 0) {
            return null;
        }
        File scd = new File(installDir, SCD_LOCAL_NAME);
        if (!mountDmgAndCopy(dmg, new String[]{SCD_BINARY_IN_DMG, SCD_LOCAL_NAME}, scd)) {
            return null;
        }
        if (!scd.setExecutable(true, false)) {
            this.listener.error("Failed to mark ssm-scd as executable");
            return null;
        }
        return scd;
    }

    /**
     * Mounts {@code dmg}, copies the first existing candidate file out to
     * {@code dest} and always detaches the mount point.
     *
     * @return {@code true} on success.
     */
    private boolean mountDmgAndCopy(File dmg, String[] possibleSourceNames, File dest) {
        File mountPoint = new File(baseDir, dmg.getName() + "-mount");
        if (!mountPoint.isDirectory() && !mountPoint.mkdirs()) {
            this.listener.error("Failed to create DMG mount point");
            return false;
        }
        try {
            Integer rc = executeCommand(Arrays.asList("hdiutil", "attach", dmg.getAbsolutePath(),
                    "-nobrowse", "-mountpoint", mountPoint.getAbsolutePath()), true);
            if (rc != 0) {
                this.listener.error("Failed to mount " + dmg.getName());
                return false;
            }
            try {
                File source = null;
                for (String name : possibleSourceNames) {
                    File candidate = new File(mountPoint, name);
                    if (candidate.isFile()) {
                        source = candidate;
                        break;
                    }
                }
                if (source == null) {
                    this.listener.error("Expected file not found inside " + dmg.getName());
                    return false;
                }
                Files.copy(source.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
                return true;
            } finally {
                executeCommand(Arrays.asList("hdiutil", "detach", mountPoint.getAbsolutePath()), true);
            }
        } catch (Exception e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Signing tools (jsign + jarsigner) -- mirrors Linux.signing()
    // ------------------------------------------------------------------

    public Integer signing() {
        String jsignUrl = getConfigProperty("jsignUrl");
        if (jsignUrl == null || !jsignUrl.startsWith("https://")) {
            this.listener.error("Invalid or missing jsignUrl in configuration");
            return 1;
        }
        try {
            this.listener.getLogger().println("\nInstalling and configuring signing tools - Jarsigner and Jsign\n");
            File jsignJar = new File(installDir, "jsign.jar");
            Integer rc = downloadAndVerify("jsign", jsignUrl, jsignJar, "jsignSha256");
            if (rc != 0) {
                this.listener.getLogger().println("\nJsign failed to install\n");
                return 1;
            }
            // Create a user-owned wrapper so "jsign" is available on PATH without root/sudo.
            File wrapper = new File(installDir, "jsign");
            String wrapperScript = "#!/bin/sh\nexec java -jar \"" + jsignJar.getAbsolutePath() + "\" \"$@\"\n";
            if (createFile(wrapper.getAbsolutePath(), wrapperScript) != 0 || !wrapper.setExecutable(true, false)) {
                this.listener.getLogger().println("\nJsign failed to install\n");
                return 1;
            }
            this.listener.getLogger().println("\nJsign successfully installed\n");
            this.listener.getLogger().println("\nJarsigner successfully installed\n");
            rc = executeCommand(Arrays.asList("chmod", "-R", "+x", installDir));
            if (rc == 0) {
                this.listener.getLogger().println("\nSigning tools installation and configuration complete\n");
            } else {
                this.listener.getLogger().println("\nFailed to configure signing tools\n");
                return 1;
            }
            this.exportedPath = this.pathVar + ":" + installDir;
            return 0;
        } catch (Exception e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return 1;
        }
    }
}
