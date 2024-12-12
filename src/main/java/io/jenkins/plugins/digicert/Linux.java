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
import java.util.List;
import java.util.Map;
import java.util.Properties;

import hudson.EnvVars;
import hudson.model.TaskListener;
import hudson.slaves.EnvironmentVariablesNodeProperty;
import hudson.slaves.NodeProperty;
import hudson.slaves.NodePropertyDescriptor;
import hudson.util.DescribableList;
import jenkins.model.Jenkins;

public class Linux {
    private final TaskListener listener;
    private final String SM_HOST;
    // lgtm[jenkins/plaintext-storage]
    private final String SM_API_KEY;
    private final String SM_CLIENT_CERT_FILE;
    // lgtm[jenkins/plaintext-storage]
    private final String SM_CLIENT_CERT_PASSWORD;
    private final String pathVar;
    private final String prompt = "bash";
    private final char c = '-';
    String dir = System.getProperty("user.dir");
    ProcessBuilder processBuilder = new ProcessBuilder();
    private Integer result;

    public Linux(TaskListener listener, String SM_HOST, String SM_API_KEY, String SM_CLIENT_CERT_FILE,
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
                .println("\nIstalling SMCTL from: https://" + SM_HOST.substring(19).replaceAll("/$", "")
                        + "/signingmanager/api-ui/v1/releases/noauth/smtools-linux-x64.tar.gz/download \n");
        executeCommand("curl -X GET https://" + SM_HOST.substring(19).replaceAll("/$", "")
                + "/signingmanager/api-ui/v1/releases/noauth/smtools-linux-x64.tar.gz/download/ -o smtools-linux-x64.tar.gz");
        result = executeCommand("tar xvf smtools-linux-x64.tar.gz > /dev/null");
        dir = dir + File.separator + "smtools-linux-x64";
        return result;
    }

    public Integer createFile(String path, String str) {

        File file = new File(path); // initialize File object and passing path as argument
        FileOutputStream fos = null;
        try {
            if (!file.createNewFile()) // creates a new file
                ;
            try {
                String name = file.getCanonicalPath();
                fos = new FileOutputStream(name, false); // true for append mode
                byte[] b = str.getBytes(StandardCharsets.UTF_8); // converts string into bytes
                fos.write(b); // writes bytes into file
                fos.close(); // close the file
                return 0;
            } catch (IOException e) {
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
                // We do have a envVars List
                envVars = envVarsNodePropertyList.get(0).getEnvVars();
            }
            envVars.put(key, value);
            instance.save();
        } catch (IOException e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
        }
    }

    public Integer signing() {
        String jsignUrl;
        InputStream input = null;
        try {
            input = Linux.class.getResourceAsStream("config.properties");
            Properties prop = new Properties();

            // load a properties file from class path, inside static method
            prop.load(input);

            // get the property value and print it out
            jsignUrl = prop.getProperty("jsignUrl");
            input.close();
            // this.listener.getLogger().println(prop.getProperty("jsignUrl"));
        } catch (Exception e) {
            try {
                if (input != null)
                    input.close();
            } catch (IOException ex) {
                ex.printStackTrace(this.listener.error(ex.getMessage()));
                return 1;
            }
            e.printStackTrace(this.listener.error(e.getMessage()));
            return 1;
        }
        try {
            this.listener.getLogger().println("\nInstalling and configuring signing tools - Jarsigner and Jsign\n");
            result = executeCommand(
                    "curl -fSslL " + jsignUrl + " -o jsign.deb && sudo dpkg --install jsign.deb > /dev/null");
            if (result == 0)
                this.listener.getLogger().println("\nJsign successfully installed\n");
            else {
                this.listener.getLogger().println("\nJsign failed to install\n");
                return 1;
            }
            this.listener.getLogger().println("\nJarsigner successfully installed\n");
            result = executeCommand("sudo chmod -R +x " + dir);
            if (result == 0)
                this.listener.getLogger().println("\nSigning tools installation and configuration complete\n");
            else {
                this.listener.getLogger().println("\nFailed to configure signing tools\n");
                return 1;
            }
            setEnvVar("PATH", this.pathVar + ":/" + dir);
            return 0;
        } catch (Exception e) {
            e.printStackTrace(this.listener.error(e.getMessage()));
            return 1;
        }
    }

    public Integer executeCommand(String command) {

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
            env.put("PATH", System.getenv("PATH") + ":/" + dir + "/smtools-linux-x64/");
            processBuilder.directory(new File(dir));
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));

            String line;

            while ((line = reader.readLine()) != null) {
                this.listener.getLogger().println(line);
            }
            int exitCode = process.waitFor();
            reader.close();
            return exitCode;
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
                "library=" + dir + "/smpkcs11.so\n" +
                "slotListIndex=0\n";
        String configPath = dir + File.separator + "pkcs11properties.cfg";

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