package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.certificates.CertificateAsyncClient
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate
import com.azure.security.keyvault.secrets.SecretAsyncClient
import com.azure.security.keyvault.secrets.models.KeyVaultSecret
import it.pagopa.touchpoint.jwtissuerservice.config.properties.AzureSecretConfigProperties
import it.pagopa.touchpoint.jwtissuerservice.models.PrivateKeyWithKid
import it.pagopa.touchpoint.jwtissuerservice.models.PublicKeyWithKid
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.OffsetDateTime
import java.util.*
import org.slf4j.LoggerFactory
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
    private val logger = LoggerFactory.getLogger(javaClass)

    fun getSecret(): Mono<KeyVaultSecret> {
        return secretClient.getSecret(azureSecretConfig.name)
    }

    fun getCerts(): Flux<KeyVaultCertificate> {
        return certClient
            .listPropertiesOfCertificateVersions(azureSecretConfig.name)
            .doOnNext {
                logger.info(
                    "CertificateProperties - name: {}, version: {}, enabled: {}, expiresOn: {}",
                    it.name,
                    it.version,
                    it.isEnabled,
                    it.expiresOn,
                )
            }
            .filter {
                it.isEnabled && (it.expiresOn == null || it.expiresOn.isAfter(OffsetDateTime.now()))
            }
            .flatMap {
                certClient
                    .getCertificateVersion(azureSecretConfig.name, it.version)
                    .onErrorResume { exception ->
                        logger.error("Failed to retrieve certificate version", exception)
                        Mono.empty()
                    }
            }
    }

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

    @Cacheable("keyStore", key = "'privateKey'")
    override fun getPrivate(): Mono<PrivateKeyWithKid> {
        return this.getKeyStore().map {
            val alias = it.aliases().nextElement()
            PrivateKeyWithKid(
                getKid(it.getCertificate(alias).encoded),
                it.getKey(alias, azureSecretConfig.password.toCharArray()) as PrivateKey,
            )
        }
    }

    override fun getPublic(): Flux<PublicKeyWithKid> {
        return this.getCerts().map {
            val x509Cert: X509Certificate =
                certFactory.generateCertificate(ByteArrayInputStream(it.cer)) as X509Certificate
            PublicKeyWithKid(getKid(it.cer), x509Cert.publicKey)
        }
    }

    private fun getKid(encodedCert: ByteArray): String {
        // Compute SHA-256 hash
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(encodedCert)
        // Convert to Base64 URL-encoded string
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }
}
