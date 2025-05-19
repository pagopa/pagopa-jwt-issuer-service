package it.pagopa.touchpoint.jwtissuerservice

import com.azure.security.keyvault.certificates.implementation.models.CertificateBundle
import com.azure.security.keyvault.certificates.implementation.models.CertificateListResult
import com.azure.security.keyvault.secrets.implementation.models.SecretAttributes
import com.azure.security.keyvault.secrets.implementation.models.SecretBundle
import it.pagopa.touchpoint.jwtissuerservice.config.properties.AzureKeyVaultClientConfigProperties
import it.pagopa.touchpoint.jwtissuerservice.config.properties.AzureSecretConfigProperties
import it.pagopa.touchpoint.jwtissuerservice.config.properties.CacheConfigProperties
import org.springframework.aot.hint.annotation.RegisterReflectionForBinding
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication
import reactor.core.publisher.Hooks

@SpringBootApplication
@RegisterReflectionForBinding(
    SecretBundle::class,
    SecretAttributes::class,
    CertificateListResult::class,
    CertificateBundle::class
)
@EnableConfigurationProperties(
    AzureSecretConfigProperties::class,
    CacheConfigProperties::class,
    AzureKeyVaultClientConfigProperties::class,
)
class JwtIssuerServiceApplication

fun main(args: Array<String>) {
    Hooks.enableAutomaticContextPropagation()
    runApplication<JwtIssuerServiceApplication>(*args)
}
