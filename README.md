# pagoPA JWT issuer service
## Overview

`pagopa-jwt-issuer-service` is a Kotlin-based microservice responsible for generating, signing, and managing JWTs used to authenticate and authorize access to secured APIs of touchpoint's services. 

It is designed to be multi domain.

This service leverages Kotlin's native compilation to achieve optimal performance and efficiency.

## Technology Stack

- Kotlin
- Spring Boot (native)

### Environment variables

These are all environment variables needed by the application:

| Variable name                             | Description                                                                                                         | type    | default |
|-------------------------------------------|---------------------------------------------------------------------------------------------------------------------|---------|---------|
| AZURE_KV_ENDPOINT                         | Azure KeyVault endpoint                                                                                             | string  |         |
| AZURE_MAX_RETRY                           | Maximum number of retries for Azure operations.                                                                     | number  |         |
| AZURE_RETRY_DELAY_MILLIS                  | Delay between retries in milliseconds for Azure operations.                                                         | number  |         |
| AZURE_MOCK_CREDENTIALS                    | When `true`, bypasses Azure AD authentication using a dummy token. Used for local/CI testing with the akv-emulator. | boolean | false   |
| SECRET_KEY_NAME                           | The name of Azure Key Vault secret containing certificates                                                          | string  |         |
| SECRET_KEY_PASSWORD                       | The password of Azure Key Vault secret used to validate keystores                                                   | string  |         |
| KEYSTORE_CACHE_MAXSIZE                    | Maximum size of the cache application uses to store keystores                                                       | number  |         |
| KEYSTORE_CACHE_TTL_MINS                   | Time to live of the cache application uses to store keystores                                                       | number  |         |
| ROOT_LOGGING_LEVEL                        | Root logging level. Possible values are 'info', 'debug', 'trace'.                                                   | string  | info    |
| SECURITY_API_KEY_SECURED_PATHS            | Secured paths for API Key                                                                                           | string  |         |
| SECURITY_API_KEY_PRIMARY                  | Primary API Key used to secure jwt-issuer service's APIs                                                            | string  |         |
| SECURITY_API_KEY_SECONDARY                | Secondary API Key used to secure jwt-issuer service's APIs                                                          | string  |         |
| WELL_KNOWN_OPENID_CONFIGURATION_BASE_PATH | Base path used to expose an OpenID Connect Provider's configuration metadata                                        | string  |         |

An example configuration of these environment variables is in the `.env.example` file.

It is recommended to create a new .env file by copying the example one, using the following command (make sure you are
in the .env.example folder):

```shell
cp .env.example .env
```

## Working with Windows

If you are developing on Windows, it is recommended the use of WSL2 combined with IntelliJ IDEA.

The IDE should be installed on Windows, with the repository cloned into a folder in WSL2. All the necessary tools will
be installed in the Linux distro of your choice.

You can find more info on how to set up the environment following the link below.

https://www.jetbrains.com/help/idea/how-to-use-wsl-development-environment-in-product.html

After setting up the WSL environment, you can test the application by building it through either Spring Boot or Docker.

## Spring Boot Native

### Requirements

1. You must use GraalVM Java SDK to build native executable locally.
   https://www.graalvm.org/downloads/. It is recommended to use SDKMAN
2. You must use GraalVM gradle plugin which allows to configure a lot of setting for native compilation, like automatic
   toolchain detection https://graalvm.github.io/native-build-tools/latest/gradle-plugin.html

If you're experiencing issue with GraalVM not found like errors, be sure to use GraalVM for the project and try to
enable automatic toolchain detection.
Also, you can use [SDKMAN](https://sdkman.io/install) to provide a better JVM env "switching".

#### Compile & Run

To compile microservice to native executable you can use the following gradle task:

```shell
gradle :nativeCompile
```

This will produce an executable inside `build/native/nativeCompile/`

N.B. Compiling into a native executable takes a long time. Locally, it is recommended to launch it normally (in java) in
order to test the service.

Also exist a gradle command to compile and run it directly:

```shell
gradle :nativeRun
```

## Docker

The project can be built and run using Docker and docker-compose. You should install Docker Desktop on Windows and go
through its settings to set up the WSL integration.

You can find more info at the following link: https://docs.docker.com/desktop/wsl/

After setting up Docker, you can use the command:

```shell
docker-compose up
```

The docker-compose up command will build the image and start the containers.

The docker-compose setup includes the `akv-emulator` service, which emulates Azure Key Vault for local and CI
integration testing. See the [Integration Testing with akv-emulator](#integration-testing-with-akv-emulator) section
below for details.

## Integration Testing with akv-emulator

### Overview

In production, the service relies on Azure Key Vault to store and retrieve EC certificates and private keys used for JWT
signing. In local development and CI environments, there is no real Azure Key Vault available. To solve this, the
docker-compose setup includes an [`akv-emulator`](https://hub.docker.com/r/decioc/akv-emulator) service — a lightweight
Node.js emulator that exposes the same REST API as Azure Key Vault for secrets and certificates.

This allows the **actual** `ReactiveAzureKVSecurityKeysService` code path to be tested end-to-end without modifications:
PKCS12 keystore loading, X.509 certificate parsing, certificate version filtering, and KID (Key ID) computation all
execute against the emulator exactly as they would against a real Azure Key Vault instance.

### Architecture

```
+---------------------+         HTTPS (port 3443)         +------------------+
|  pagopa-jwt-issuer  | ------------------------------>   |   akv-emulator   |
|     -service        |   (self-signed TLS certificate)   |  (decioc/akv-    |
|                     |                                   |   emulator)      |
|  - Reads PKCS12     |   GET /secrets/testName           |                  |
|    secret           |   GET /certificates/testName/...  |  - Serves mock   |
|  - Reads cert       |                                   |    secrets &     |
|    versions         |                                   |    certificates  |
|  - Signs JWTs       |                                   |    from JSON     |
+---------------------+                                   +------------------+
        |                                                         |
        | mounts                                                  | mounts
        | local-testing/test-certs/                               | local-testing/test-certs/
        |   truststore.jks                                        |   ec-key.pem
        |   (to trust self-signed cert)                           |   ec-cert.pem
        |                                                         | local-testing/test-data/
        |                                                         |   test-secrets.json
        |                                                         |   test-certificates.json
```

### Why HTTPS is required

The Azure SDK's `KeyVaultCredentialPolicy` enforces HTTPS at the HTTP pipeline level — it rejects any `http://` URL
with the error `Token credentials require a URL using the HTTPS protocol scheme` before even sending an HTTP request.
This is a hardcoded security check in the SDK that cannot be bypassed, even with a mock `TokenCredential`. For this
reason, the emulator must serve HTTPS using a self-signed TLS certificate.

### Repository structure for the emulator

```
local-testing/
  test-certs/
    ec-key.pem              # EC private key (secp256r1) — TLS key for emulator + PKCS12 source
    ec-cert.pem             # Self-signed X.509 cert (CN=akv-emulator, SAN=DNS:akv-emulator,DNS:localhost)
    test-keystore.p12       # PKCS12 keystore (key + cert, password: testPass)
    truststore.jks          # JVM truststore containing ec-cert.pem (password: changeit)
  test-data/
    test-secrets.json       # Emulator fixture: Base64-encoded PKCS12 as a KV secret
    test-certificates.json  # Emulator fixture: DER-encoded certificate for KV certificates
```

> **Note on committed credentials:** All files in `local-testing/` contain test-only cryptographic material used
> exclusively for local/CI integration tests. The same private key material is present in multiple forms (PEM file,
> PKCS12, and Base64-encoded inside `test-secrets.json`). These have no relation to production secrets and are safe to
> commit publicly. Production environments use real Azure Key Vault with CA-issued certificates.

### How the mock credentials work

In CI and local development, `DefaultAzureCredentialBuilder` would fail because no Azure AD identity is available. The
`AZURE_MOCK_CREDENTIALS=true` environment variable activates a code path in `AzureConfig.kt` that replaces the real
credential with a no-op `TokenCredential` returning a static dummy token. The emulator does not validate authentication
tokens, so any value is accepted.

When `AZURE_MOCK_CREDENTIALS` is not set or is `false` (the default), the service uses `DefaultAzureCredentialBuilder`
as before, so production behavior is completely unaffected.

### How to run integration tests locally

1. Copy the example environment file and start the containers:

```shell
cp .env.example .env
docker-compose up -d --build
```

2. Wait for the service to start (typically under 1 second for the native image), then verify the emulator is serving
   fixtures:

```shell
curl -k https://localhost:3443/secrets/testName
```

You should see a JSON response with the Base64-encoded PKCS12 value.

3. Test all endpoints:

```shell
# Liveness probe — should return {"status":"UP"}
curl http://localhost:8080/actuator/health/liveness

# JWKS endpoint — should return one EC key with alg=ES256
curl http://localhost:8080/tokens/keys

# OpenID configuration — should return JWKS URI, token endpoint, etc.
curl http://localhost:8080/.well-known/openid-configuration

# Token request without API key — should return 401 Unauthorized
curl -v -X POST http://localhost:8080/tokens

# Token request with API key — should return 200 with a signed JWT
curl -X POST http://localhost:8080/tokens \
  -H "x-api-key: PRIMARY-KEY" \
  -H "Content-Type: application/json" \
  -d '{"audience": "test-audience", "duration": 3600, "privateClaims": {"sub": "test-user"}}'
```

### Regenerating the test certificates

If the test certificates expire or need to be regenerated for any reason (e.g., adding a new SAN entry), follow these
steps:

1. Generate a new EC key and self-signed certificate with the correct Subject Alternative Names:

```shell
openssl ecparam -genkey -name prime256v1 -noout -out local-testing/test-certs/ec-key.pem

openssl req -new -x509 -key local-testing/test-certs/ec-key.pem -out local-testing/test-certs/ec-cert.pem \
  -days 3650 -subj "/CN=akv-emulator" \
  -addext "subjectAltName=DNS:akv-emulator,DNS:localhost"
```

The SAN must include `DNS:akv-emulator` (the Docker service name the application connects to) and optionally
`DNS:localhost` (for testing from the host machine with `curl -k`).

2. Package into a PKCS12 keystore. The password must match the `SECRET_KEY_PASSWORD` in `.env.example`:

```shell
openssl pkcs12 -export -out local-testing/test-certs/test-keystore.p12 \
  -inkey local-testing/test-certs/ec-key.pem -in local-testing/test-certs/ec-cert.pem -password pass:testPass
```

3. Regenerate the JVM truststore:

```shell
rm -f local-testing/test-certs/truststore.jks
keytool -importcert -alias akv-emulator \
  -file local-testing/test-certs/ec-cert.pem \
  -keystore local-testing/test-certs/truststore.jks \
  -storepass changeit \
  -noprompt
```

4. Regenerate the fixture JSON files with the new Base64-encoded values:

```shell
P12_B64=$(base64 -w0 local-testing/test-certs/test-keystore.p12)
CERT_DER_B64=$(openssl x509 -in local-testing/test-certs/ec-cert.pem -outform DER | base64 -w0)
```

Then update `local-testing/test-data/test-secrets.json` (replace the `value` field with the new `$P12_B64`) and
`local-testing/test-data/test-certificates.json` (replace the `cer` field with the new `$CERT_DER_B64`).

5. Verify the fixtures are valid JSON and restart docker-compose:

```shell
python3 -c "import json; json.load(open('local-testing/test-data/test-secrets.json')); print('OK')"
python3 -c "import json; json.load(open('local-testing/test-data/test-certificates.json')); print('OK')"
docker-compose down && docker-compose up -d --build
```

### Troubleshooting

| Symptom                                                           | Cause                                                     | Fix                                                                               |
|-------------------------------------------------------------------|-----------------------------------------------------------|-----------------------------------------------------------------------------------|
| `Token credentials require a URL using the HTTPS protocol scheme` | Azure SDK rejects `http://` URLs at the pipeline level    | Ensure `AZURE_KV_ENDPOINT` uses `https://` and the emulator is configured for TLS |
| `SSLHandshakeException: No name matching <host> found`            | Certificate CN/SAN does not match the connection hostname | Regenerate the certificate with `-addext "subjectAltName=DNS:akv-emulator"`       |
| `Received Malformed Secret Id URL from KV Service`                | Certificate fixture `properties.id` is not a full URL     | Set `id` to `https://akv-emulator:3443/certificates/<name>/<version>`             |
| `/tokens/keys` returns `{"keys":[]}`                              | Certificate version lookup failed (see errors above)      | Check emulator logs and certificate fixture format                                |
| `401 Unauthorized` with valid API key                             | Using wrong header name                                   | Use `x-api-key` header, not `Ocp-Apim-Subscription-Key`                           |
| `400 Missing required creator property 'duration'`                | Incomplete request body for `POST /tokens`                | Include all required fields: `audience`, `duration`, `privateClaims`              |
| Emulator log: `Failed to load SSL key/certificate`                | TLS cert/key files not mounted or wrong path              | Check `SSL_KEY_PATH` and `SSL_CERT_PATH` env vars in docker-compose               |

#### Tips

The main issue with native image is related to Java Reflection.
GraalVM produces a metadata files containing reflection data. There is also a repository containing the metadata of some
of the most widely used external libraries. You can include this metadata via the gradle plugin

```gradle
graalvmNative {
    metadataRepository {
        enabled.set(true)
        version.set("0.2.6")
    }
}
```

Spring using AOT try automatically to do the best, but you can also find issues.
Here https://docs.spring.io/spring-framework/reference/core/aot.html#aot.hints you can find a lot of tips, like
`@RegisterReflectionForBinding`

#### Dependency lock

This feature use the content of `gradle.lockfile` to check the declared dependencies against the locked one.

If a transitive dependencies have been upgraded the build will fail because of the locked version mismatch.

The following command can be used to upgrade dependency lockfile:

```shell
./gradlew dependencies --write-locks 
```

Running the above command will cause the `gradle.lockfile` to be updated against the current project dependency
configuration

#### Dependency verification

This feature is enabled by adding the gradle `./gradle/verification-metadata.xml` configuration file.

Perform checksum comparison against dependency artifact (jar files, zip, ...) and metadata (pom.xml, gradle module
metadata, ...) used during build
and the ones stored into `verification-metadata.xml` file raising error during build in case of mismatch.

The following command can be used to recalculate dependency checksum:

```shell
./gradlew --write-verification-metadata sha256 clean spotlessApply build --no-build-cache --refresh-dependencies
```

In the above command the `clean`, `spotlessApply` `build` tasks where chosen to be run
in order to discover all transitive dependencies used during build and also the ones used during
spotless apply task used to format source code.

The above command will upgrade the `verification-metadata.xml` adding all the newly discovered dependencies' checksum.
Those checksum should be checked against a trusted source to check for corrispondence with the library author published
checksum.

`/gradlew --write-verification-metadata sha256` command appends all new dependencies to the verification files but does
not remove
entries for unused dependencies.

This can make this file grow every time a dependency is upgraded.

To detect and remove old dependencies make the following steps:

1. Delete, if present, the `gradle/verification-metadata.dryrun.xml`
2. Run the gradle write-verification-metadata in dry-mode (this will generate a verification-metadata-dryrun.xml file
   leaving untouched the original verification file)
3. Compare the verification-metadata file and the verification-metadata.dryrun one checking for differences and removing
   old unused dependencies

The 1-2 steps can be performed with the following commands

```Shell
rm -f ./gradle/verification-metadata.dryrun.xml 
./gradlew --write-verification-metadata sha256 clean spotlessApply build --dry-run
```

The resulting `verification-metadata.xml` modifications must be reviewed carefully checking the generated
dependencies checksum against official websites or other secure sources.

If a dependency is not discovered during the above command execution it will lead to build errors.

You can add those dependencies manually by modifying the `verification-metadata.xml`
file adding the following component:

```xml

<verification-metadata>
    <!-- other configurations... -->
    <components>
        <!-- other components -->
        <component group="GROUP_ID" name="ARTIFACT_ID" version="VERSION">
            <artifact name="artifact-full-name.jar">
                <sha256 value="sha value"
                        origin="Description of the source of the checksum value"/>
            </artifact>
            <artifact name="artifact-pom-file.pom">
                <sha256 value="sha value"
                        origin="Description of the source of the checksum value"/>
            </artifact>
        </component>
    </components>
</verification-metadata>
```

Add those components at the end of the components list and then run the

```shell
./gradlew --write-verification-metadata sha256 clean spotlessApply build --no-build-cache --refresh-dependencies
```

that will reorder the file with the added dependencies checksum in the expected order.

Finally, you can add new dependencies both to gradle.lockfile writing verification metadata running

```shell
 ./gradlew dependencies --write-locks --write-verification-metadata sha256 --no-build-cache --refresh-dependencies
```

For more information read the
following [article](https://docs.gradle.org/8.1/userguide/dependency_verification.html#sec:checksum-verification)

## Contributors 👥

Made with ❤️ by PagoPA S.p.A.

### Maintainers

See `CODEOWNERS` file
