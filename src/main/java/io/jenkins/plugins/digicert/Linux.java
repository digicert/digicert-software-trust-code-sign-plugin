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
import java.util.Arrays;
import java.util.Map;

import hudson.model.TaskListener;
import hudson.util.Secret;

public class Linux extends BaseAgent {

    private static final String SMTOOLS_ARTIFACT = "smtools-linux-x64.tar.gz";
    private static final String SMTOOLS_DIR_NAME = "smtools-linux-x64";
    private static final String SMCTL_ARTIFACT = "smctl";

    /** Directory that should be placed on the PATH for child processes. */
    private String installDir;

    public Linux(TaskListener listener, String SM_HOST, Secret SM_API_KEY, String SM_CLIENT_CERT_FILE,
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
        String url = cdnUrl(SMCTL_ARTIFACT);
        if (url == null) {
            return 1;
        }
        File smctl = new File(baseDir, SMCTL_ARTIFACT);
        Integer rc = downloadAndVerify(SMCTL_ARTIFACT, url, smctl, "smctlLinuxSha256");
        if (rc != 0) {
            return rc;
        }
        if (!smctl.setExecutable(true, false)) {
            this.listener.error("Failed to mark smctl as executable");
            return 1;
        }
        installDir = baseDir;
        this.exportedPath = this.pathVar + ":" + installDir;
        this.listener.getLogger().println("\nsmctl successfully installed\n");
        this.setupSucceeded = true;
        return simpleSign(smctl.getAbsolutePath());
    }

    // ------------------------------------------------------------------
    // Full setup: smtools bundle + jsign/jarsigner.
    // ------------------------------------------------------------------

    private Integer fullSetup(String os) {
        Integer result = install(os);
        if (result == 0) {
            this.listener.getLogger().println("\nSMCTL Installation Complete\n");
        } else {
            this.listener.getLogger().println("\nSMCTL Installation Failed\n");
            return result;
        }

        this.listener.getLogger().println("\nCreating PKCS11 Config File\n");
        String str = "name=signingmanager\n" +
                "library=" + installDir + "/smpkcs11.so\n" +
                "slotListIndex=0\n";
        String configPath = installDir + File.separator + "pkcs11properties.cfg";
        result = createFile(configPath, str);
        if (result == 0) {
            this.listener.getLogger()
                    .println("\nPKCS11 config file successfully created at location: " + configPath + "\n");
        } else {
            this.listener.getLogger().println("\nFailed to create PKCS11 config file\n");
            return result;
        }

        result = signing();
        if (result != 0) {
            return result;
        }

        // smctl ships inside the smtools bundle and is on the PATH, so honour a
        // signing request issued in the same step.
        this.setupSucceeded = true;
        return simpleSign("smctl");
    }

    public Integer install(String os) {
        this.listener.getLogger().println("\nAgent type: " + os);
        String url = cdnUrl(SMTOOLS_ARTIFACT);
        if (url == null) {
            return 1;
        }
        File archive = new File(baseDir, SMTOOLS_ARTIFACT);
        Integer result = downloadAndVerify(SMTOOLS_ARTIFACT, url, archive, "smtoolsLinuxSha256");
        if (result != 0) {
            return result;
        }
        result = executeCommand(Arrays.asList("tar", "xf", archive.getAbsolutePath()), true);
        installDir = baseDir + File.separator + SMTOOLS_DIR_NAME;
        dir = installDir;
        return result;
    }

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