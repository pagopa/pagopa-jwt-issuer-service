package it.pagopa.touchpoint.jwtissuerservice.config

import com.azure.identity.DefaultAzureCredentialBuilder
import com.azure.security.keyvault.keys.KeyAsyncClient
import com.azure.security.keyvault.keys.KeyClientBuilder
import it.pagopa.touchpoint.jwtissuerservice.services.SecurityKeysService
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.ApplicationListener
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class AzureConfig {

    @Bean
    fun azureKeyVaultKeyClient(
        @Value("\${azure.keyvault.endpoint}") azureKeyVaultEndpoint: String
    ): KeyAsyncClient {
        return KeyClientBuilder()
            .vaultUrl(azureKeyVaultEndpoint)
            .credential(DefaultAzureCredentialBuilder().build())
            .buildAsyncClient()
    }

    @Bean
    fun basicsApplicationListener(
        jwtKeysService: SecurityKeysService
    ): ApplicationListener<ApplicationReadyEvent> {
        return ApplicationListener {
            println(jwtKeysService.getKey().block())
            println(jwtKeysService.getPrivate())
            println(jwtKeysService.getPublic().block())
            println(jwtKeysService.getPrivate().block())
        }
    }
}
