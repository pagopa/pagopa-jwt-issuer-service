package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.keys.KeyAsyncClient
import com.azure.security.keyvault.keys.models.KeyVaultKey
import java.security.PrivateKey
import java.security.PublicKey
import org.springframework.beans.factory.annotation.Value
import org.springframework.cache.annotation.Cacheable
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class SecurityKeysService(
    private val keyClient: KeyAsyncClient,
    @Value("\${jwt.key.name}") private val jwtKeyName: String,
) {
    @Cacheable("rsaKeys")
    fun getKey(): Mono<KeyVaultKey> {
        return keyClient.getKey(jwtKeyName)
    }

    fun getPrivate(): Mono<PrivateKey> {
        return this.getKey().map { key -> key.key.toRsa().private }
    }

    fun getPublic(): Mono<PublicKey> {
        return this.getKey().map { key -> key.key.toRsa().public }
    }
}
