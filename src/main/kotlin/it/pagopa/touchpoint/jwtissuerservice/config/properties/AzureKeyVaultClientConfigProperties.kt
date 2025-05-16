package it.pagopa.touchpoint.jwtissuerservice.config.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("azure.keyvault")
data class AzureKeyVaultClientConfigProperties(
    val endpoint: String,
    val maxRetries: Int,
    val retryDelayMillis: Long,
)
