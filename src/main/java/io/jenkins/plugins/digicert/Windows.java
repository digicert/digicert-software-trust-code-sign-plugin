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
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.nio.file.Files;

import hudson.model.TaskListener;
import hudson.util.Secret;

public class Windows extends BaseAgent {

    private static final String SM_TOOLS_DIR = "C:\\Program Files\\DigiCert\\DigiCert One Signing Manager Tools";
    private static final String SMTOOLS_ARTIFACT = "smtools-windows-x64.msi";
    private static final String SMCTL_ARTIFACT = "smctl.exe";

    /** Directory of the standalone smctl in simple signing mode. */
    private String installDir;

    public Windows(TaskListener listener, String SM_HOST, Secret SM_API_KEY, String SM_CLIENT_CERT_FILE,
            Secret SM_CLIENT_CERT_PASSWORD, String pathVar, SigningConfig config, String workspace) {
        super(listener, SM_HOST, SM_API_KEY, SM_CLIENT_CERT_FILE, SM_CLIENT_CERT_PASSWORD, pathVar, config, workspace);
        this.installDir = workspace;
    }

    @Override
    protected void addToolPathToEnv(Map<String, String> env) {
        // On Windows the environment map is case-insensitive; use the canonical "PATH"
        // key and fall back to "Path" when reading the current value.
        String existing = System.getenv("PATH");
        if (existing == null) existing = System.getenv("Path");
        if (existing == null) existing = "";
        env.put("PATH", existing + ";" + SM_TOOLS_DIR + ";" + installDir + ";");
    }

    @Override
    public Integer call(String os) throws IOException {
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
        Integer rc = downloadAndVerify(SMCTL_ARTIFACT, url, smctl, "smctlWindowsSha256");
        if (rc != 0) {
            return rc;
        }
        installDir = baseDir;
        this.exportedPath = this.pathVar + ";" + installDir + ";";
        this.listener.getLogger().println("\nsmctl successfully installed\n");
        this.setupSucceeded = true;
        return simpleSign(smctl.getAbsolutePath());
    }

    // ------------------------------------------------------------------
    // Full setup: smtools msi + nuget/signtool/jarsigner.
    // ------------------------------------------------------------------

    private Integer fullSetup(String os) throws IOException {
        Integer result = install(os);
        if (result == 0) {
            this.listener.getLogger().println("\nSMCTL Installation Complete\n");
            // Ensure smctl (from the MSI) and jarsigner (from the agent JDK) are on PATH
            // immediately, even if the auxiliary tool setup below fails.
            String jdkBin = jdkBinDir();
            this.exportedPath = this.pathVar + ";" + SM_TOOLS_DIR + ";" + installDir
                    + (jdkBin != null ? ";" + jdkBin : "") + ";";
        } else {
            this.listener.getLogger().println("\nSMCTL Installation Failed\n");
            return result;
        }

        this.listener.getLogger().println("\nCreating PKCS11 Config File\n");
        String str = "name=signingmanager\n" +
                "library = \"C:\\\\Program Files\\\\DigiCert\\\\DigiCert One Signing Manager Tools\\\\smpkcs11.dll\"\n"
                + "slotListIndex=0\n";
        String configPath = getConfigProperty("configPath");
        if (configPath == null) {
            this.listener.error("Missing configPath in configuration");
            return 1;
        }
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
            // Auxiliary signing tools (nuget/signtool/jsign) failed to install, but
            // smctl from the MSI is already installed and on PATH. Setup can continue;
            // only smctl-based signing and the healthcheck are required for most flows.
            this.listener.getLogger().println("\nWARNING: One or more auxiliary signing tools (nuget/signtool)"
                    + " failed to install. smctl is still available. Continuing.\n");
        }

        // smctl is installed with the smtools bundle and is on the PATH.
        this.setupSucceeded = true;
        return simpleSign(new File(SM_TOOLS_DIR, SMCTL_ARTIFACT).getAbsolutePath());
    }

    public Integer install(String os) {
        this.listener.getLogger().println("\nAgent type: " + os);
        String url = cdnUrl(SMTOOLS_ARTIFACT);
        if (url == null) {
            return 1;
        }
        File installer = new File(dir, SMTOOLS_ARTIFACT);
        Integer result = downloadAndVerify(SMTOOLS_ARTIFACT, url, installer, "smtoolsWindowsSha256");
        if (result != 0) {
            return result;
        }
        result = executeCommand(Arrays.asList("msiexec", "/i", installer.getAbsolutePath(), "/quiet", "/qn"));
        if (SM_API_KEY != null && SM_CLIENT_CERT_FILE != null && SM_CLIENT_CERT_PASSWORD != null) {
            executeCommand(Arrays.asList("C:\\Windows\\System32\\certutil.exe", "-csp",
                    "DigiCert Signing Manager KSP", "-key", "-user"), true);
            executeCommand(Arrays.asList(new File(SM_TOOLS_DIR, "smksp_cert_sync.exe").getAbsolutePath()), true);
            executeCommand(Arrays.asList(new File(SM_TOOLS_DIR, SMCTL_ARTIFACT).getAbsolutePath(),
                    "windows", "certsync"), true);
        }
        return result;
    }

    public List<Path> findByFileName(Path path, String fileName) throws IOException {
        List<Path> result;
        try (Stream<Path> pathStream = Files.find(path,
                Integer.MAX_VALUE,
                (p, basicFileAttributes) -> p.getFileName().toString().equalsIgnoreCase(fileName))) {
            result = pathStream.collect(Collectors.toList());
        }
        return result;
    }

    public String findNewestFolder() throws IOException {
        String signtoolFolder = getConfigProperty("signtoolFolder");
        if (signtoolFolder == null) {
            return "";
        }
        Path parentFolder = Paths.get(signtoolFolder);
        File[] children = parentFolder.toFile().listFiles();
        if (children == null) {
            this.listener.getLogger().println("Signtool folder is empty");
            return "";
        }
        Optional<File> mostRecentFolder = Arrays.stream(children)
                .filter(File::isDirectory)
                .max((f1, f2) -> Long.compare(f1.lastModified(), f2.lastModified()));
        if (mostRecentFolder.isPresent()) {
            return mostRecentFolder.get().getPath();
        }
        this.listener.getLogger().println("Signtool folder is empty");
        return "";
    }

    public Integer signing() {
        try {
            this.listener.getLogger()
                    .println("\nInstalling and configuring signing tools - Jarsigner, Signtool and Nuget\n");
            String nugetUrl = getConfigProperty("nugetUrl");
            String signtoolUrl = getConfigProperty("signtoolUrl");

            // --- Nuget (best effort) ---
            if (nugetUrl != null) {
                File nuget = new File(dir, "nuget.exe");
                if (downloadAndVerify("nuget", nugetUrl, nuget, "nugetSha256") == 0) {
                    this.listener.getLogger()
                            .println("\nNuget successfully installed at " + nuget.getAbsolutePath() + "\n");
                } else {
                    this.listener.getLogger().println("\nNuget failed to install (continuing)\n");
                }
            }

            // --- Signtool (best effort: install if possible, then locate) ---
            if (signtoolUrl != null) {
                File winsdk = new File(dir, "winsdksetup.exe");
                if (downloadAndVerify("signtool", signtoolUrl, winsdk, "signtoolSha256") == 0) {
                    Integer rc = executeCommand(Arrays.asList(winsdk.getAbsolutePath(), "/norestart", "/quiet"));
                    if (rc == 0) {
                        this.listener.getLogger().println("\nSigntool installer completed\n");
                    } else {
                        this.listener.getLogger().println("\nSigntool installer returned exit code " + rc
                                + " (it may already be installed). Will try to locate an existing signtool.\n");
                    }
                } else {
                    this.listener.getLogger()
                            .println("\nSigntool download failed; will try to locate an existing signtool.\n");
                }
            }

            // Locate signtool whether freshly installed or pre-existing on the agent.
            String[] signtoolPaths = locateSigntoolDirs();

            // smctl's "Signtool 32 bit" healthcheck looks for an executable literally
            // named "signtool_32"; the SDK only ships "signtool.exe" in the x86 folder.
            // Create the alias in-place (same dir preserves its DLL dependencies) so the
            // 32-bit tool maps too.
            if (signtoolPaths[1] != null) {
                try {
                    File x86Signtool = new File(signtoolPaths[1], "signtool.exe");
                    File alias = new File(signtoolPaths[1], "signtool_32.exe");
                    if (x86Signtool.isFile() && !alias.isFile()) {
                        Files.copy(x86Signtool.toPath(), alias.toPath());
                        this.listener.getLogger()
                                .println("\nCreated signtool_32.exe alias for smctl 32-bit mapping\n");
                    }
                } catch (Exception ex) {
                    this.listener.getLogger()
                            .println("Could not create signtool_32.exe alias: " + ex.getMessage());
                }
            }

            // --- jarsigner comes from the agent's own JDK ---
            String jdkBin = jdkBinDir();
            if (jdkBin != null) {
                this.listener.getLogger().println("\nJarsigner located in JDK: " + jdkBin + "\n");
            } else {
                this.listener.getLogger().println("\nJarsigner not found: the Jenkins agent is running on a JRE"
                        + " without jarsigner, or java.home is unset. Install a JDK on the agent to sign .jar files.\n");
            }

            // Build the PATH exported to subsequent pipeline steps. Directories only.
            StringBuilder sb = new StringBuilder();
            sb.append(this.pathVar);
            sb.append(";").append(SM_TOOLS_DIR);
            sb.append(";").append(dir);
            if (jdkBin != null) {
                sb.append(";").append(jdkBin);
            }
            if (signtoolPaths[0] != null) {
                sb.append(";").append(signtoolPaths[0]);
            }
            if (signtoolPaths[1] != null) {
                sb.append(";").append(signtoolPaths[1]);
            }
            sb.append(";");
            this.exportedPath = sb.toString();

            this.listener.getLogger().println("\nSigning tools configuration complete\n");

            // certsync populates the Windows certificate store and only works when the
            // signing credentials are present. Skip it (and surface a non-zero exit code)
            // otherwise, to avoid spamming logs and hiding real failures.
            if (SM_API_KEY != null && SM_CLIENT_CERT_FILE != null && SM_CLIENT_CERT_PASSWORD != null) {
                Integer certsyncRc = executeCommand(Arrays.asList(new File(SM_TOOLS_DIR, SMCTL_ARTIFACT).getAbsolutePath(),
                        "windows", "certsync"), true);
                if (certsyncRc != 0) {
                    this.listener.getLogger().println("\nWARNING: 'smctl windows certsync' returned exit code "
                            + certsyncRc + "; the Windows certificate store may not be fully populated.\n");
                }
            }
        } catch (Exception e) {
            this.listener.error("Exception while installing auxiliary signing tools: "
                    + e.getClass().getName() + ": " + e.getMessage());
            e.printStackTrace(this.listener.getLogger());
            return 1;
        }
        return 0;
    }

    /** Locates x64 and x86 {@code signtool.exe} directories under the Windows Kits bin folder. */
    private String[] locateSigntoolDirs() {
        String[] dirs = new String[2]; // [0]=x64, [1]=x86
        try {
            String signtoolFolder = findNewestFolder();
            if (signtoolFolder.isEmpty()) {
                return dirs;
            }
            List<Path> paths = findByFileName(Paths.get(signtoolFolder), "signtool.exe");
            for (Path p : paths) {
                String lower = p.toString().toLowerCase();
                Path parent = p.getParent();
                if (parent == null) {
                    continue;
                }
                if (lower.contains("\\x64\\")) {
                    dirs[0] = parent.toString();
                } else if (lower.contains("\\x86\\")) {
                    dirs[1] = parent.toString();
                }
            }
            if (dirs[0] != null || dirs[1] != null) {
                this.listener.getLogger()
                        .println("\nSigntool located (x64=" + dirs[0] + ", x86=" + dirs[1] + ")\n");
            } else {
                this.listener.getLogger().println("\nSigntool not found under " + signtoolFolder + "\n");
            }
        } catch (Exception e) {
            this.listener.getLogger().println("Could not locate signtool: " + e.getMessage());
        }
        return dirs;
    }

    /** @return the agent JDK's bin directory if it contains jarsigner, else {@code null}. */
    private String jdkBinDir() {
        String javaHome = System.getProperty("java.home");
        if (javaHome == null) {
            return null;
        }
        File bin = new File(javaHome, "bin");
        if (new File(bin, "jarsigner.exe").isFile()) {
            return bin.getAbsolutePath();
        }
        // java.home may point at a JRE nested inside a JDK; check the parent's bin.
        File parent = new File(javaHome).getParentFile();
        if (parent != null) {
            File parentBin = new File(parent, "bin");
            if (new File(parentBin, "jarsigner.exe").isFile()) {
                return parentBin.getAbsolutePath();
            }
        }
        return null;
    }
}
