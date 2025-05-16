package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.certificates.CertificateAsyncClient
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate
import com.azure.security.keyvault.secrets.SecretAsyncClient
import com.azure.security.keyvault.secrets.models.KeyVaultSecret
import it.pagopa.touchpoint.jwtissuerservice.config.properties.AzureSecretConfigProperties
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import org.springframework.cache.annotation.Cacheable
import org.springframework.stereotype.Component
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

@Component
class ReactiveAzureKVSecurityKeysService(
    private val secretClient: SecretAsyncClient,
    private val certClient: CertificateAsyncClient,
    private val azureSecretConfig: AzureSecretConfigProperties,
) : IReactiveSecurityKeysService {
    private val keystore = KeyStore.getInstance("PKCS12")
    private val certFactory = CertificateFactory.getInstance("X.509")

    fun getSecret(): Mono<KeyVaultSecret> {
        return secretClient.getSecret(azureSecretConfig.name)
    }

    fun getCerts(): Flux<KeyVaultCertificate> {
        return certClient
            .listPropertiesOfCertificateVersions(azureSecretConfig.name)
            .filter { it.isEnabled }
            .flatMap { certClient.getCertificateVersion(azureSecretConfig.name, it.version) }
    }

    @Cacheable("keyStore")
    fun getKeyStore(): Mono<KeyStore> {
        return this.getSecret().map {
            val decodedPfx = Base64.getDecoder().decode(it.value)
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

    override fun getPublic(): Flux<PublicKey> {
        return this.getCerts().map {
            val x509Cert: X509Certificate =
                certFactory.generateCertificate(ByteArrayInputStream(it.cer)) as X509Certificate
            x509Cert.publicKey
        }
    }
}
