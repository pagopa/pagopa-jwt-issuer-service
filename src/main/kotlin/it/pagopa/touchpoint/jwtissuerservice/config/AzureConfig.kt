package it.pagopa.touchpoint.jwtissuerservice.config

import com.azure.identity.DefaultAzureCredentialBuilder
import com.azure.security.keyvault.secrets.SecretAsyncClient
import com.azure.security.keyvault.secrets.SecretClientBuilder
import it.pagopa.touchpoint.jwtissuerservice.services.ReactiveAzureKVSecurityKeysService
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.ApplicationListener
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
    fun basicsApplicationListener(
        jwtKeysService: ReactiveAzureKVSecurityKeysService
    ): ApplicationListener<ApplicationReadyEvent> {
        return ApplicationListener {
            println(jwtKeysService.getSecret().map { println(it.value) }.block())
            println(jwtKeysService.getPublic().block())
            println(jwtKeysService.getPrivate().block()?.format)
            println(jwtKeysService.getPrivate().block()?.algorithm)
        }
    }
}
