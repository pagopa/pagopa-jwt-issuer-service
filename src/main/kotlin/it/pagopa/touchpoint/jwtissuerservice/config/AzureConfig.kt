package it.pagopa.touchpoint.jwtissuerservice.config

import com.azure.identity.DefaultAzureCredentialBuilder
import com.azure.security.keyvault.certificates.CertificateAsyncClient
import com.azure.security.keyvault.certificates.CertificateClientBuilder
import com.azure.security.keyvault.secrets.SecretAsyncClient
import com.azure.security.keyvault.secrets.SecretClientBuilder
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class AzureConfig {

    @Bean
    fun azureKeyVaultSecretClient(
        @Value("\${azure.keyvault.endpoint}") azureKeyVaultEndpoint: String
    ): SecretAsyncClient {
        return SecretClientBuilder()
            .vaultUrl(azureKeyVaultEndpoint)
            .credential(DefaultAzureCredentialBuilder().build())
            .buildAsyncClient()
    }

    @Bean
    fun azureKeyVaultCertClient(
        @Value("\${azure.keyvault.endpoint}") azureKeyVaultEndpoint: String
    ): CertificateAsyncClient {
        return CertificateClientBuilder()
            .vaultUrl(azureKeyVaultEndpoint)
            .credential(DefaultAzureCredentialBuilder().build())
            .buildAsyncClient()
    }
}
