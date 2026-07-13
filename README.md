# Code signing with Software Trust Manager Jenkins plugin

The code Signing with Software Trust Manager Jenkins plugin enables
keypair-based signing workflows that improve software security and
integrate with DevOps processes across Windows, Linux, and macOS agents.

The plugin accelerates the installation and configuration of Software
Trust Manager client tools and supported signing tools, helping
developers prepare Jenkins pipelines for secure signing workflows.

It supports both simple signing with `smctl` and traditional signing using
tools such as SignTool, jarsigner, NuGet, and jSign through KSP or
PKCS#11 integrations.

## Features

- Supports Windows, Linux, and macOS Jenkins agents.

- Installs and configures Software Trust Manager client and signing tools.

- Supports simple signing without third-party signing tools.

- Supports traditional signing using KSP and PKCS#11 integrations.

- Performs setup and signing in a single pipeline step.

- Automatically provides required environment variables to subsequent pipeline stages.

- Supports `SHA-256` verification of downloaded artifacts.

- Supports alternate download sources for restricted or air-gapped
environments.

- Maintains compatibility with existing setup-only Jenkins pipelines.

## Supported signing approaches

**Simple signing**

Simple signing uses `smctl` to sign files directly from the `SoftwareTrustManagerSetup`
pipeline step.

- No third-party signing tools are required.

- Only the standalone `smctl` binary is downloaded.

- Suitable for lightweight or containerized environments.

- Suitable for agents where other signing tools are already installed.

- Supports setup and signing in a single pipeline step.

When both `input`and `keypairAlias` are provided, the step installs the
required tools and signs the specified files in a single invocation. A
separate signing stage is not required.

**Traditional signing**

Traditional signing uses third-party signing tools with Software Trust
Manager integrations.

- Supported integrations include:

  - KSP

  - PKCS#11

- Supported tools include SignTool, jarsigner, NuGet, jSign, and other
compatible signing utilities.

**Note**: If your workflow does not require these tools, we recommend using `simpleSigningMode: true`
with the `SoftwareTrustManagerSetup` step for a
simplified signing experience.

## What's new

This release introduces the following enhancements:

- **Simple signing mode**: Sign files directly from the setup step without
requiring third-party signing tools.

- **Integrated setup and signing**: Install the required tools and sign files
in a single pipeline step.

- **Cross-platform support**: Run signing workflows on Windows, Linux, and
macOS agents.

- **Standalone smctl download**: Download only the smctl binary instead of a
full MSI, DMG, or Linux archive.

- **Automatic environment variable injection**: Make resolved environment
variables, including `PATH`, available to all subsequent pipeline stages.

- **Configurable download source**: Use the `digicertCdn` parameter to specify
an alternate artifact location.

- **Artifact integrity verification**: Validate downloaded artifacts using
configured `SHA-256` checksums.

- **Flexible credential handling**: Supply the client certificate as either a
Jenkins Secret text or Secret file credential.

- **Bulk signing controls**: Configure bulk signing, fail-fast behavior,
timestamping, and exit-code handling.

## Backward compatibility

This release maintains compatibility with existing Jenkins pipelines.

- Existing pipelines that use the setup step only do not require changes.

- When `input`and `keypairAlias`are not provided, the step installs and
configures the signing tools without performing signing.

- Existing Jenkins credential IDs remain supported.

- Existing traditional signing workflows can continue to use KSP and
PKCS#11 integrations.

- Manual `PATH `configuration is no longer required for subsequent stages.

## Parameters

The `SoftwareTrustManagerSetup` pipeline step accepts the following
optional parameters. When no signing parameters are provided, the step installs and
configures the signing tools only, maintaining compatibility with
earlier releases.

| Parameter | Type | Default | Description | 
|---|---|---|---| 
| digicertCdn | String | DigiCert CDN | Base URL from which signing tool artifacts are downloaded. Override when using a mirror or air-gapped environment. | 
| input | String | — | Path or glob of file(s) to sign. Required together with `keypairAlias` to trigger signing within the setup step. | 
| keypairAlias | String | — | Alias of the keypair to use for signing. Required together with `input` to trigger signing within the setup step. | 
| simpleSigningMode | boolean | false | When `true`, only `smctl` is downloaded (no full MSI/DMG installation). Useful for lightweight environments that already have the signing tools installed. | 
| timestamp | boolean | true | Whether to apply a trusted timestamp to the signature. | 
| digestAlg | String | — | Digest algorithm to use (e.g. SHA256). Defaults to the tool's built-in default when not set. | 
| failFast | boolean | true | Abort the build on the first signing error. | 
| unsigned | boolean | false | Produce an unsigned artifact (dry-run mode). | 
| bulkSign | boolean | false | Enable bulk signing mode for large sets of files. | 
| zeroExitCodeOnFailure | boolean | false | Return exit code 0 even when signing fails. |


## Credentials

The plugin reads the following Jenkins credentials by ID:
| Credential ID | Type | Description | 
|---|---|---| 
| SM_HOST | Secret text | DigiCert ONE host URL |
| SM_API_KEY | Secret text | API key for Software Trust Manager |
| SM_CLIENT_CERT_FILE | `Secret text` **or** `Secret file` | Client certificate. Use a `Secret text`credential to supply a file path already present on the agent, or a `Secret file` credential to have Jenkins copy the certificate bytes to the agent automatically. |
| SM_CLIENT_CERT_PASSWORD | Secret text | Password for the client certificate |

## Environment variables

After the setup step completes, the plugin automatically provides all
resolved environment variables, including updates to `PATH`, into the
pipeline run.

These variables are available to all subsequent stages in the same
pipeline run. A manual `withEnv` wrapper or environment {} block is not
required.

## Artifact downloads

The plugin automatically downloads the required Software Trust Manager
artifacts during pipeline execution.

By default, no additional configuration is required. For environments
that restrict outbound network access or use an internal artifact
mirror, use the `digicertCdn` parameter to specify an alternate download
source.

Note: Use the digicertCdn parameter only when your organization requires
a custom download source, such as an internal repository or an
air-gapped environment.

## Artifact integrity verification

`SHA-256`checksums for downloaded artifacts can be configured in
`config.properties`.

When a checksum is available, the plugin verifies the downloaded
artifact before using it. If a checksum is not configured, the plugin
logs a warning and continues without verification.

**Windows signing requirements**

**Note**: For Windows-based signing workflows, run `smctl windows certsync` 
before signing to populate the Windows certificate store with the
required certificates. After signing, use `smctl sign verify` to verify
the signature.

## Documentation

For comprehensive installation, configuration, and usage guidance, see: [Jenkins plugin for keypair signing](https://docs.digicert.com/en/software-trust-manager/ci-cd-integrations-and-deployment-pipelines/plugins/jenkins/install-client-tools-for-gpg-keypair-signing-on-jenkins.html)

Jenkins plugin for keypair signing

## Feedback and issues

For questions, feedback, or issues, contact DigiCert.

## Learn more

To learn more about centralizing and automating code signing workflows
with Software Trust Manager, contact Sales/Enquiry or visit:

https://www.digicert.com/signing/software-trust-manager
