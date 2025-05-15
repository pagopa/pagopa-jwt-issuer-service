package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.secrets.SecretAsyncClient
import com.azure.security.keyvault.secrets.models.KeyVaultSecret
import it.pagopa.touchpoint.jwtissuerservice.config.properties.AzureSecretConfigProperties
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*
import org.springframework.cache.annotation.Cacheable
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class ReactiveAzureKVSecurityKeysService(
    private val secretClient: SecretAsyncClient,
    private val azureSecretConfig: AzureSecretConfigProperties,
) : IReactiveSecurityKeysService {

    fun getSecret(): Mono<KeyVaultSecret> {
        return secretClient.getSecret(azureSecretConfig.name)
    }

    @Cacheable("keyStore")
    fun getKeyStore(): Mono<KeyStore> {
        return this.getSecret().map {
            val decodedPfx = Base64.getDecoder().decode(it.value)
            val keystore = KeyStore.getInstance("PKCS12")
            keystore.load(
                ByteArrayInputStream(decodedPfx),
                azureSecretConfig.password.toCharArray(),
            )
            keystore
        }
    }

    override fun getPrivate(): Mono<PrivateKey> {
        return this.getKeyStore().map {
            it.getKey(it.aliases().nextElement(), azureSecretConfig.password.toCharArray())
                as PrivateKey
        }
    }

    override fun getPublic(): Mono<PublicKey> {
        return this.getKeyStore().map { it.getCertificate(it.aliases().nextElement()).publicKey }
    }
}
