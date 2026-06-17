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

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import org.jenkinsci.plugins.plaincredentials.FileCredentials;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.jenkinsci.plugins.workflow.steps.SynchronousNonBlockingStepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.google.common.collect.ImmutableSet;

import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.model.EnvironmentContributingAction;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import hudson.security.ACL;
import hudson.util.Secret;
import jenkins.model.Jenkins;

public class Pipeline extends Step {

    // All parameters are optional. When none of the signing parameters are
    // supplied the step behaves exactly like earlier releases (setup only).
    private String digicertCdn = SigningConfig.DEFAULT_CDN;
    private String input;
    private String keypairAlias;
    private boolean simpleSigningMode = false;
    private boolean timestamp = true;
    private String digestAlg;
    private boolean failFast = true;
    private boolean unsigned = false;
    private boolean bulkSign = false;
    private boolean zeroExitCodeOnFailure = false;

    @DataBoundConstructor
    public Pipeline() {
    }

    public String getDigicertCdn() {
        return digicertCdn;
    }

    @DataBoundSetter
    public void setDigicertCdn(String digicertCdn) {
        this.digicertCdn = digicertCdn;
    }

    public String getInput() {
        return input;
    }

    @DataBoundSetter
    public void setInput(String input) {
        this.input = input;
    }

    public String getKeypairAlias() {
        return keypairAlias;
    }

    @DataBoundSetter
    public void setKeypairAlias(String keypairAlias) {
        this.keypairAlias = keypairAlias;
    }

    public boolean isSimpleSigningMode() {
        return simpleSigningMode;
    }

    @DataBoundSetter
    public void setSimpleSigningMode(boolean simpleSigningMode) {
        this.simpleSigningMode = simpleSigningMode;
    }

    public boolean isTimestamp() {
        return timestamp;
    }

    @DataBoundSetter
    public void setTimestamp(boolean timestamp) {
        this.timestamp = timestamp;
    }

    public String getDigestAlg() {
        return digestAlg;
    }

    @DataBoundSetter
    public void setDigestAlg(String digestAlg) {
        this.digestAlg = digestAlg;
    }

    public boolean isFailFast() {
        return failFast;
    }

    @DataBoundSetter
    public void setFailFast(boolean failFast) {
        this.failFast = failFast;
    }

    public boolean isUnsigned() {
        return unsigned;
    }

    @DataBoundSetter
    public void setUnsigned(boolean unsigned) {
        this.unsigned = unsigned;
    }

    public boolean isBulkSign() {
        return bulkSign;
    }

    @DataBoundSetter
    public void setBulkSign(boolean bulkSign) {
        this.bulkSign = bulkSign;
    }

    public boolean isZeroExitCodeOnFailure() {
        return zeroExitCodeOnFailure;
    }

    @DataBoundSetter
    public void setZeroExitCodeOnFailure(boolean zeroExitCodeOnFailure) {
        this.zeroExitCodeOnFailure = zeroExitCodeOnFailure;
    }

    SigningConfig toSigningConfig() {
        return new SigningConfig(digicertCdn, input, keypairAlias, simpleSigningMode, timestamp, digestAlg,
                failFast, unsigned, bulkSign, zeroExitCodeOnFailure);
    }

    @Override
    public StepExecution start(StepContext context) throws Exception {
        return new ExecutionImpl(context, this);
    }

    private static class ExecutionImpl extends SynchronousNonBlockingStepExecution<Void> {
        private static final long serialVersionUID = 1L;
        private final transient Pipeline step;
        private EnvVars envVars = null;
        private final SigningConfig signingConfig;

        ExecutionImpl(StepContext context, Pipeline step) throws Exception {
            super(context);
            this.step = step;
            this.envVars = context.get(EnvVars.class);
            this.signingConfig = step.toSigningConfig();
        }

        @Override
        public Void run() throws IOException, InterruptedException, ExecutionException {
            TaskListener listener = getContext().get(TaskListener.class);
            FilePath filePath = getContext().get(FilePath.class);
            assert filePath != null;
            VirtualChannel virtualChannel = filePath.getChannel();
            assert virtualChannel != null;

            Map<String, Secret> credentialLookup = stmCredentialLookup();
            byte[] clientCertFileBytes = resolveClientCertFileBytes();

            Map<String, String> resolvedEnv = virtualChannel.callAsync(
                    new AgentInfo(listener, envVars, credentialLookup, signingConfig, clientCertFileBytes, filePath.getRemote())).get();

            if (resolvedEnv == null) {
                throw new IOException("SoftwareTrustManagerSetup failed — check the build log for details.");
            }
            Run<?, ?> run = getContext().get(Run.class);
            if (run != null) {
                final Map<String, String> envSnapshot = resolvedEnv;
                run.addAction(new EnvironmentContributingAction() {
                    @Override
                    public void buildEnvironment(Run<?, ?> r, EnvVars e) {
                        e.overrideAll(envSnapshot);
                    }
                    @Override public String getIconFileName() { return null; }
                    @Override public String getDisplayName() { return null; }
                    @Override public String getUrlName() { return null; }
                });
            }
            return null;
        }

        private Map<String, Secret> stmCredentialLookup() {
            Secret host = getCredential(Constants.HOST_ID);
            Secret apiKey = getCredential(Constants.API_KEY_ID);
            // SM_CLIENT_CERT_FILE: only look up as StringCredentials (path).
            // If it was stored as FileCredentials the bytes are handled separately
            // via resolveClientCertFileBytes() and written to a temp file on the agent.
            Secret clientCertFile = getStringCredential(Constants.CLIENT_CERT_FILE_ID);
            Secret clientCertPassword = getCredential(Constants.CLIENT_CERT_PASSWORD_ID);

            Map<String, Secret> map = new HashMap<String, Secret>();

            if (null != host) {
                map.put(Constants.HOST_ID, host);
            }

            if (null != apiKey) {
                map.put(Constants.API_KEY_ID, apiKey);
            }

            if (null != clientCertFile) {
                map.put(Constants.CLIENT_CERT_FILE_ID, clientCertFile);
            }

            if (null != clientCertPassword) {
                map.put(Constants.CLIENT_CERT_PASSWORD_ID, clientCertPassword);
            }

            return map;
        }

        private Secret getCredential(String credentialID) {
            StandardCredentials credential = CredentialsMatchers.firstOrNull(
                    CredentialsProvider.lookupCredentials(StandardCredentials.class, Jenkins.get(), ACL.SYSTEM,
                            List.of()),
                    CredentialsMatchers.withId(credentialID));

            if (credential != null) {
                if (credential instanceof StringCredentials) {
                    return ((StringCredentials) credential).getSecret();
                }
            }

            return null;
        }

        /**
         * Like {@link #getCredential} but only matches {@link StringCredentials}.
         * Used for SM_CLIENT_CERT_FILE when the fallback path-as-string is needed.
         */
        private Secret getStringCredential(String credentialID) {
            StandardCredentials credential = CredentialsMatchers.firstOrNull(
                    CredentialsProvider.lookupCredentials(StandardCredentials.class, Jenkins.get(), ACL.SYSTEM,
                            List.of()),
                    CredentialsMatchers.withId(credentialID));

            if (credential instanceof StringCredentials) {
                return ((StringCredentials) credential).getSecret();
            }
            return null;
        }

        /**
         * Reads the raw bytes of the client certificate when the user has stored it
         * as a Jenkins "Secret file" credential with ID {@code SM_CLIENT_CERT_FILE}.
         * Returns {@code null} when no such credential exists (fall back to path resolution).
         */
        private byte[] resolveClientCertFileBytes() {
            StandardCredentials credential = CredentialsMatchers.firstOrNull(
                    CredentialsProvider.lookupCredentials(StandardCredentials.class, Jenkins.get(), ACL.SYSTEM,
                            List.of()),
                    CredentialsMatchers.withId(Constants.CLIENT_CERT_FILE_ID));

            if (credential instanceof FileCredentials) {
                try (InputStream is = ((FileCredentials) credential).getContent()) {
                    return is.readAllBytes();
                } catch (IOException e) {
                    return null;
                }
            }
            return null;
        }
    }

    @Extension
    public static class DescriptorImpl extends StepDescriptor {

        @Override
        public String getDisplayName() {
            return "SoftwareTrustManagerSetup";
        }

        @Override
        public String getFunctionName() {
            return "SoftwareTrustManagerSetup";
        }

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return ImmutableSet.of(Run.class, TaskListener.class);
        }
    }
}