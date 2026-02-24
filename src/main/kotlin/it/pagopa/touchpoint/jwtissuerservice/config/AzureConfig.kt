package it.pagopa.touchpoint.jwtissuerservice.config

import com.azure.core.credential.AccessToken
import com.azure.core.credential.TokenCredential
import com.azure.core.credential.TokenRequestContext
import com.azure.core.http.policy.FixedDelay
import com.azure.core.http.policy.RetryPolicy
import com.azure.identity.DefaultAzureCredentialBuilder
import com.azure.security.keyvault.certificates.CertificateAsyncClient
import com.azure.security.keyvault.certificates.CertificateClientBuilder
import com.azure.security.keyvault.secrets.SecretAsyncClient
import com.azure.security.keyvault.secrets.SecretClientBuilder
import it.pagopa.touchpoint.jwtissuerservice.config.properties.AzureKeyVaultClientConfigProperties
import java.time.Duration
import java.time.OffsetDateTime
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import reactor.core.publisher.Mono

@Configuration
class AzureConfig(
    @Autowired private val azureKeyVaultClientConfigProperties: AzureKeyVaultClientConfigProperties
) {

    /**
     * Returns mock credentials for integration tests with the akv-emulator (which performs no
     * authentication), or real Azure AD credentials for production. Controlled by the
     * `azure.keyvault.mock-credentials` property (default: false).
     */
    private fun buildCredential(): TokenCredential {
        if (azureKeyVaultClientConfigProperties.mockCredentials) {
            return TokenCredential { _: TokenRequestContext ->
                Mono.just(AccessToken("mock-token", OffsetDateTime.now().plusHours(1)))
            }
        }
        return DefaultAzureCredentialBuilder().build()
    }

    @Bean
    fun azureKeyVaultSecretClient(): SecretAsyncClient {
        return SecretClientBuilder()
            .vaultUrl(azureKeyVaultClientConfigProperties.endpoint)
            .retryPolicy(
                RetryPolicy(
                    FixedDelay(
                        azureKeyVaultClientConfigProperties.maxRetries, // Maximum retries
                        Duration.ofMillis(
                            azureKeyVaultClientConfigProperties.retryDelayMillis
                        ), // Delay between retries in milliseconds
                    )
                )
            )
            .credential(buildCredential())
            .buildAsyncClient()
    }

    @Bean
    fun azureKeyVaultCertClient(): CertificateAsyncClient {
        return CertificateClientBuilder()
            .vaultUrl(azureKeyVaultClientConfigProperties.endpoint)
            .retryPolicy(
                RetryPolicy(
                    FixedDelay(
                        azureKeyVaultClientConfigProperties.maxRetries, // Maximum retries
                        Duration.ofMillis(
                            azureKeyVaultClientConfigProperties.retryDelayMillis
                        ), // Delay between retries in milliseconds
                    )
                )
            )
            .credential(buildCredential())
            .buildAsyncClient()
    }
}
