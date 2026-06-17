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
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.Map;

import hudson.EnvVars;
import hudson.model.TaskListener;
import hudson.util.Secret;
import jenkins.security.MasterToSlaveCallable;

public class AgentInfo extends MasterToSlaveCallable<Map<String, String>, Throwable> {
    private final TaskListener listener;
    private final EnvVars env;
    private String SM_HOST;
    private Secret SM_API_KEY;
    private String SM_CLIENT_CERT_FILE;
    private Secret SM_CLIENT_CERT_PASSWORD;
    private String path;
    private Integer result;
    private Map<String, Secret> credentialLookup;
    private final SigningConfig config;
    private final byte[] clientCertFileBytes;
    private final String workspace;

    public AgentInfo(TaskListener listener, EnvVars env, Map<String, Secret> credentialLookup, SigningConfig config, byte[] clientCertFileBytes, String workspace) {
        this.listener = listener;
        this.env = env;
        this.credentialLookup = credentialLookup;
        this.config = config;
        this.clientCertFileBytes = clientCertFileBytes;
        this.workspace = workspace;
    }

    private String getStringValue(String credentialID) {
        String envCredential = env.get(credentialID) != null ? env.get(credentialID)
                : System.getenv(credentialID);

        if (envCredential != null) {
            return envCredential;
        }
        Secret secret = credentialLookup.get(credentialID);
        return secret != null ? secret.getPlainText() : null;
    }

    private Secret getSecretValue(String credentialID) {
        String envCredential = env.get(credentialID) != null ? env.get(credentialID)
                : System.getenv(credentialID);

        if (envCredential != null) {
            return Secret.fromString(envCredential);
        }
        return credentialLookup.get(credentialID);
    }

    public Map<String, String> call() throws Throwable {

        String os = System.getProperty("os.name");

        SM_HOST = getStringValue(Constants.HOST_ID);
        SM_API_KEY = getSecretValue(Constants.API_KEY_ID);
        // Priority 1: file bytes uploaded directly as a Jenkins Secret file credential
        if (clientCertFileBytes != null && clientCertFileBytes.length > 0) {
            File tempCert = File.createTempFile("sm-client-cert-", ".p12");
            tempCert.deleteOnExit();
            try (FileOutputStream fos = new FileOutputStream(tempCert)) {
                fos.write(clientCertFileBytes);
            }
            SM_CLIENT_CERT_FILE = tempCert.getAbsolutePath();
        } else {
            // Priority 2: env var or StringCredentials path
            SM_CLIENT_CERT_FILE = getStringValue(Constants.CLIENT_CERT_FILE_ID);
        }
        SM_CLIENT_CERT_PASSWORD = getSecretValue(Constants.CLIENT_CERT_PASSWORD_ID);
        // Resolve PATH case-insensitively — Linux agents use "PATH", Windows agents "Path"
        path = env.get("PATH");
        if (path == null) path = env.get("Path");
        if (path == null) path = env.get("path");
        if (path == null) path = System.getenv("PATH");

        BaseAgent agent;
        if (os.toLowerCase().contains("windows")) {
            agent = new Windows(this.listener, this.SM_HOST, this.SM_API_KEY, this.SM_CLIENT_CERT_FILE,
                    this.SM_CLIENT_CERT_PASSWORD, this.path, this.config, this.workspace);
        } else if (os.toLowerCase().contains("mac") || os.toLowerCase().contains("darwin")) {
            agent = new MacOS(this.listener, this.SM_HOST, this.SM_API_KEY, this.SM_CLIENT_CERT_FILE,
                    this.SM_CLIENT_CERT_PASSWORD, this.path, this.config, this.workspace);
        } else {
            agent = new Linux(this.listener, this.SM_HOST, this.SM_API_KEY, this.SM_CLIENT_CERT_FILE,
                    this.SM_CLIENT_CERT_PASSWORD, this.path, this.config, this.workspace);
        }
        result = agent.call(os);
        // 'result' carries the signing exit code (non-zero when e.g. some files in a
        // bulk directory are unsupported); it is reported by simpleSign() and must NOT
        // be treated as a setup failure here.
        Map<String, String> resolvedEnv = new HashMap<>();
        if (SM_HOST != null) resolvedEnv.put(Constants.HOST_ID, SM_HOST);
        if (SM_API_KEY != null) resolvedEnv.put(Constants.API_KEY_ID, SM_API_KEY.getPlainText());
        if (SM_CLIENT_CERT_FILE != null) resolvedEnv.put(Constants.CLIENT_CERT_FILE_ID, SM_CLIENT_CERT_FILE);
        if (SM_CLIENT_CERT_PASSWORD != null) resolvedEnv.put(Constants.CLIENT_CERT_PASSWORD_ID, SM_CLIENT_CERT_PASSWORD.getPlainText());
        if (agent.exportedPath != null) resolvedEnv.put("PATH", agent.exportedPath);

        // Only a genuine SETUP failure (smctl install / PKCS11 config) should fail the
        // step. A non-zero signing exit code does not nullify the result, mirroring the
        // behaviour where setup succeeds and signing reports its own outcome.
        if (!agent.setupSucceeded)
            return null; // signals setup failure to Pipeline
        return resolvedEnv;
    }
}