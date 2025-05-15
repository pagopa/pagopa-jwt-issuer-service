package it.pagopa.touchpoint.jwtissuerservice.config

import com.azure.identity.DefaultAzureCredentialBuilder
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
}
