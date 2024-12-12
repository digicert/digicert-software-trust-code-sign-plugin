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

import java.util.Map;

import hudson.EnvVars;
import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;

public class AgentInfo extends MasterToSlaveCallable<Boolean, Throwable> {
    private final TaskListener listener;
    private final EnvVars env;
    private String SM_HOST;
    // lgtm[jenkins/plaintext-storage]
    private String SM_API_KEY;
    private String SM_CLIENT_CERT_FILE;
    // lgtm[jenkins/plaintext-storage]
    private String SM_CLIENT_CERT_PASSWORD;
    private String path;
    private Integer result;
    private Map<String, String> credentialLookup;

    public AgentInfo(TaskListener listener, EnvVars env, Map<String, String> credentialLookup) {
        this.listener = listener;
        this.env = env;
        this.credentialLookup = credentialLookup;
    }

    public String getValue(String credentialID) {
        String envCredential = env.get(credentialID) != null ? env.get(credentialID)
                : System.getenv(credentialID);

        if (envCredential != null) {
            return envCredential;
        } else {
            return credentialLookup.get(credentialID);
        }
    }

    public Boolean call() throws Throwable {

        String os = System.getProperty("os.name");

        SM_HOST = getValue(Constants.HOST_ID);
        SM_API_KEY = getValue(Constants.API_KEY_ID);
        SM_CLIENT_CERT_FILE = getValue(Constants.CLIENT_CERT_FILE_ID);
        SM_CLIENT_CERT_PASSWORD = getValue(Constants.CLIENT_CERT_PASSWORD_ID);
        path = env.get("path") != null ? env.get("path") : System.getenv("path");

        if (os.toLowerCase().contains("windows")) {
            Windows w = new Windows(this.listener, this.SM_HOST, this.SM_API_KEY, this.SM_CLIENT_CERT_FILE,
                    this.SM_CLIENT_CERT_PASSWORD, this.path);
            result = w.call(os);
        } else {
            Linux l = new Linux(this.listener, this.SM_HOST, this.SM_API_KEY, this.SM_CLIENT_CERT_FILE,
                    this.SM_CLIENT_CERT_PASSWORD, this.path);
            result = l.call(os);
        }
        if (result == 1)
            return false;
        return true;
    }
}