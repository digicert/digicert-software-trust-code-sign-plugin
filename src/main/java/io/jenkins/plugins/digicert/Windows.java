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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import hudson.EnvVars;
import hudson.model.TaskListener;
import hudson.slaves.EnvironmentVariablesNodeProperty;
import hudson.slaves.NodeProperty;
import hudson.slaves.NodePropertyDescriptor;
import hudson.util.DescribableList;
import jenkins.model.Jenkins;

public class Windows {
    private final TaskListener listener;
    private final String SM_HOST;
    // lgtm[jenkins/plaintext-storage]
    private final String SM_API_KEY;
    private final String SM_CLIENT_CERT_FILE;
    // lgtm[jenkins/plaintext-storage]
    private final String SM_CLIENT_CERT_PASSWORD;
    private final String pathVar;
    private final String prompt = "cmd.exe";
    private final char c = '/';
    String dir = System.getProperty("user.dir");
    ProcessBuilder processBuilder = new ProcessBuilder();
    private Integer result;

    public Windows(TaskListener listener, String SM_HOST, String SM_API_KEY, String SM_CLIENT_CERT_FILE,
            String SM_CLIENT_CERT_PASSWORD, String pathVar) {
        this.listener = listener;
        this.SM_HOST = SM_HOST;
        this.SM_API_KEY = SM_API_KEY;
        this.SM_CLIENT_CERT_FILE = SM_CLIENT_CERT_FILE;
        this.SM_CLIENT_CERT_PASSWORD = SM_CLIENT_CERT_PASSWORD;
        this.pathVar = pathVar;
    }

    public Integer install(String os) {
        this.listener.getLogger().println("\nAgent type: " + os);
        this.listener.getLogger()
                .println("\nInstalling SMCTL from: https://" + SM_HOST.substring(19).replaceAll("/$", "")
                        + "/signingmanager/api-ui/v1/releases/noauth/smtools-windows-x64.msi/download \n");
        executeCommand("curl -X GET  https://" + SM_HOST.substring(19).replaceAll("/$", "")
                + "/signingmanager/api-ui/v1/releases/noauth/smtools-windows-x64.msi/download -o smtools-windows-x64.msi");
        result = executeCommand("msiexec /i smtools-windows-x64.msi /quiet /qn");
        if (SM_API_KEY != null && SM_CLIENT_CERT_FILE != null && SM_CLIENT_CERT_PASSWORD != null) {
            executeCommand(
                    "C:\\Windows\\System32\\certutil.exe -csp \"DigiCert Signing Manager KSP\" -key -user > NUL 2> NUL");
            executeCommand("smksp_cert_sync.exe > NUL 2> NUL");
            executeCommand("smctl windows certsync > NUL 2> NUL");
        }
        return result;
    }

    public Integer createFile(String path, String str) {

        File file = new File(path); // initialize File object and passing path as argument
        FileOutputStream fos = null;
        try {
            if (!file.createNewFile())
                ;
            try {
                String name = file.getCanonicalPath();
                fos = new FileOutputStream(name, false); // true for append mode
                byte[] b = str.getBytes(StandardCharsets.UTF_8); // converts string into bytes
                fos.write(b); // writes bytes into file
                fos.close(); // close the file
                return 0;
            } catch (Exception e) {
                if (fos != null)
                    fos.close();
                e.printStackTrace(this.listener.error(e.getMessage()));
                return 1;
            }
        } catch (IOException e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return 1;
        }
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
        String signtoolFolder;
        try (InputStream input = Windows.class.getResourceAsStream("config.properties")) {

            Properties prop = new Properties();
            prop.load(input);

            signtoolFolder = prop.getProperty("signtoolFolder");

        } catch (IOException e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return "";
        }
        Path parentFolder = Paths.get(signtoolFolder);
        Optional<File> mostRecentFolder = Arrays
                .stream(parentFolder.toFile().listFiles())
                .filter(f -> f.isDirectory())
                .max(
                        (f1, f2) -> Long.compare(f1.lastModified(),
                                f2.lastModified()));
        if (mostRecentFolder.isPresent()) {
            File mostRecent = mostRecentFolder.get();
            return mostRecent.getPath();
        } else {
            this.listener.getLogger().println("Signtool folder is empty");
            return "";
        }
    }

    public void setEnvVar(String key, String value) {
        try {
            Jenkins instance = Jenkins.get();

            DescribableList<NodeProperty<?>, NodePropertyDescriptor> globalNodeProperties = instance
                    .getGlobalNodeProperties();
            List<EnvironmentVariablesNodeProperty> envVarsNodePropertyList = globalNodeProperties
                    .getAll(EnvironmentVariablesNodeProperty.class);

            EnvironmentVariablesNodeProperty newEnvVarsNodeProperty = null;
            EnvVars envVars = null;

            if (envVarsNodePropertyList == null || envVarsNodePropertyList.size() == 0) {
                newEnvVarsNodeProperty = new hudson.slaves.EnvironmentVariablesNodeProperty();
                globalNodeProperties.add(newEnvVarsNodeProperty);
                envVars = newEnvVarsNodeProperty.getEnvVars();
            } else {
                envVars = envVarsNodePropertyList.get(0).getEnvVars();
            }
            envVars.put(key, value);
            instance.save();
        } catch (IOException e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
        }
    }

    public Integer executeCommand(String command) {
        int exitCode;
        try {
            processBuilder.command(prompt, c + "c", command);
            Map<String, String> env = processBuilder.environment();
            if (SM_API_KEY != null)
                env.put(Constants.API_KEY_ID, SM_API_KEY);
            if (SM_CLIENT_CERT_PASSWORD != null)
                env.put(Constants.CLIENT_CERT_PASSWORD_ID, SM_CLIENT_CERT_PASSWORD);
            if (SM_CLIENT_CERT_FILE != null)
                env.put(Constants.CLIENT_CERT_FILE_ID, SM_CLIENT_CERT_FILE);
            if (SM_HOST != null)
                env.put(Constants.HOST_ID, SM_HOST);
            env.put("path",
                    System.getenv("path") + ";C:\\Program Files\\DigiCert\\DigiCert One Signing Manager Tools;");
            processBuilder.directory(new File(dir));
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));

            String line;

            while ((line = reader.readLine()) != null) {
                this.listener.getLogger().println(line);
            }
            exitCode = process.waitFor();
            reader.close();
        } catch (IOException e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return 1;
        } catch (InterruptedException e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return 1;
        } catch (Exception e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return 1;
        }
        return exitCode;
    }

    public Integer signing() {
        String nugetUrl;
        String signtoolUrl;
        try {
            this.listener.getLogger()
                    .println("\nInstalling and configuring signing tools - Jarsigner, Signtool and Nuget\n");
            // Windows.class.getResource("config.properties");
            try (InputStream input = Windows.class.getResourceAsStream("config.properties")) {

                Properties prop = new Properties();

                prop.load(input);

                nugetUrl = prop.getProperty("nugetUrl");
                // this.listener.getLogger().println(prop.getProperty("nugetUrl"));
                signtoolUrl = prop.getProperty("signtoolUrl");
                // this.listener.getLogger().println(prop.getProperty("signtoolUrl"));
            } catch (IOException e) {
                e.printStackTrace(this.listener.error(e.getMessage()));
                return 1;
            }
            result = executeCommand("curl -X GET " + nugetUrl + " -o nuget.exe > NUL");

            if (result == 0)
                this.listener.getLogger().println("\nNuget successfully installed\n");
            else {
                this.listener.getLogger().println("\nNuget failed to install\n");
                return 1;
            }
            executeCommand("curl -X GET " + signtoolUrl + " -o winsdksetup.exe > NUL");
            result = executeCommand("winsdksetup.exe /norestart /quiet");

            if (result == 0)
                this.listener.getLogger().println("\nSigntool successfully installed\n");
            else {
                this.listener.getLogger().println("\nSigntool failed to install\n");
                return 1;
            }

            String signtoolFolder = findNewestFolder();
            if (signtoolFolder.equals(""))
                return 1;
            else
                ;
            Path path = Paths.get(signtoolFolder);
            List<Path> paths = findByFileName(path, "signtool.exe");
            ListIterator<Path> iter = paths.listIterator();
            String[] signtoolPaths = new String[2];
            while (iter.hasNext()) {
                String s = (iter.next()).toString();
                if ((s.substring(30)).contains("x64"))
                    signtoolPaths[0] = s.substring(0, s.length() - 13);
                if ((s.substring(30)).contains("x86"))
                    signtoolPaths[1] = s.substring(0, s.length() - 13);
            }
            setEnvVar("PATH", this.pathVar + ";" + dir + ";" + signtoolPaths[0] + ";" + signtoolPaths[1]
                    + ";C:\\Program Files\\DigiCert\\DigiCert One Signing Manager Tools;");
            this.listener.getLogger().println("\nJarsigner successfully installed\n");
            this.listener.getLogger().println("\nSigning tools installation and configuration complete\n");

            executeCommand("set " + "path=%path%;" + dir + ";" + signtoolPaths[0] + ";" + signtoolPaths[1] +
                    " & smctl windows certsync > NUL 2> NUL");
        } catch (Exception e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return 1;
        }
        return 0;
    }

    public Integer call(String os) throws IOException {

        result = install(os);

        if (result == 0)
            this.listener.getLogger().println("\nSMCTL Istallation Complete\n");
        else {
            this.listener.getLogger().println("\nSMCTL Istallation Failed\n");
            return result;
        }

        this.listener.getLogger().println("\nCreating PKCS11 Config File\n");

        String str = "name=signingmanager\n" +
                "library = \"C:\\\\Program Files\\\\DigiCert\\\\DigiCert One Signing Manager Tools\\\\smpkcs11.dll\"\n"
                +
                "slotListIndex=0\n";

        String configPath;
        try (InputStream input = Windows.class.getResourceAsStream("config.properties")) {

            Properties prop = new Properties();
            prop.load(input);

            configPath = prop.getProperty("configPath");

        } catch (IOException e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return 1;
        }
        result = createFile(configPath, str);

        if (result == 0)
            this.listener.getLogger()
                    .println("\nPKCS11 config file successfully created at location: " + configPath + "\n");
        else {
            this.listener.getLogger().println("\nFailed to create PKCS11 config file\n");
            return result;
        }

        // signing
        result = signing();
        return result;
    }
}
