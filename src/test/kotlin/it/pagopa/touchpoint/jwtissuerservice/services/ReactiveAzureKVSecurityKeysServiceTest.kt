package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.certificates.CertificateAsyncClient
import com.azure.security.keyvault.certificates.models.CertificateProperties
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate
import com.azure.security.keyvault.secrets.SecretAsyncClient
import com.azure.security.keyvault.secrets.models.KeyVaultSecret
import it.pagopa.touchpoint.jwtissuerservice.config.properties.AzureSecretConfigProperties
import it.pagopa.touchpoint.jwtissuerservice.models.PrivateKeyWithKid
import it.pagopa.touchpoint.jwtissuerservice.models.PublicKeyWithKid
import it.pagopa.touchpoint.jwtissuerservice.utils.AzureTestUtils
import it.pagopa.touchpoint.jwtissuerservice.utils.KeyGenerationTestUtils.Companion.generatePKCS12Certificate
import it.pagopa.touchpoint.jwtissuerservice.utils.KeyGenerationTestUtils.Companion.generatePKCS12CertificateAsBase64
import it.pagopa.touchpoint.jwtissuerservice.utils.KeyGenerationTestUtils.Companion.getKeyPairEC
import it.pagopa.touchpoint.jwtissuerservice.utils.KeyGenerationTestUtils.Companion.getKeyStoreWithPKCS12Certificate
import it.pagopa.touchpoint.jwtissuerservice.utils.KeyGenerationTestUtils.Companion.getKid
import java.time.OffsetDateTime
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.mock
import org.mockito.kotlin.*
import reactor.core.publisher.Mono
import reactor.test.StepVerifier

class ReactiveAzureKVSecurityKeysServiceTest {
    private val azureTestUtils: AzureTestUtils = AzureTestUtils()
    private val secretClient: SecretAsyncClient = mock()
    private val certClient: CertificateAsyncClient = mock()
    private val azureSecretConfig: AzureSecretConfigProperties =
        AzureSecretConfigProperties(name = "testName", password = "testPassword")
    private val securityKeysService =
        ReactiveAzureKVSecurityKeysService(
            secretClient = secretClient,
            certClient = certClient,
            azureSecretConfig = azureSecretConfig,
        )

    @Test
    fun `Should get secret successfully`() = runTest {
        // pre-conditions
        val secretTest = KeyVaultSecret("testName", "testValue")
        given { secretClient.getSecret(any()) }.willReturn(Mono.just(secretTest))

        val obtainedSecret = securityKeysService.getSecret().block()
        assertThat(obtainedSecret).isEqualTo(secretTest)
        verify(secretClient, times(1)).getSecret("testName")
    }

    @Test
    fun `Should get certificates successfully`() = runTest {
        // pre-conditions
        val certProperties1 = mock(CertificateProperties::class.java)
        val certProperties2 = mock(CertificateProperties::class.java)
        val keyVaultCertificate = mock(KeyVaultCertificate::class.java)
        given { certProperties1.isEnabled }.willReturn(true)
        given { certProperties2.isEnabled }.willReturn(false)
        given { certProperties1.expiresOn }.willReturn(OffsetDateTime.now().plusHours(1))
        given { certProperties2.expiresOn }.willReturn(OffsetDateTime.now().minusHours(1))

        given { certClient.listPropertiesOfCertificateVersions(any()) }
            .willReturn(
                azureTestUtils.getCertificatePropertiesPagedFlux(
                    listOf(certProperties1, certProperties2)
                )
            )

        given { certClient.getCertificateVersion(anyString(), anyOrNull()) }
            .willReturn(Mono.just(keyVaultCertificate))

        StepVerifier.create(securityKeysService.getCerts())
            .expectNext(keyVaultCertificate)
            .verifyComplete()
        verify(certClient, times(1)).getCertificateVersion(any(), anyOrNull())
    }

    @Test
    fun `Should only get not expired certificates`() = runTest {
        // pre-conditions
        val certProperties1 = mock(CertificateProperties::class.java)
        val certProperties2 = mock(CertificateProperties::class.java)
        val keyVaultCertificate = mock(KeyVaultCertificate::class.java)
        given { certProperties1.isEnabled }.willReturn(true)
        given { certProperties2.isEnabled }.willReturn(true)
        given { certProperties1.expiresOn }.willReturn(OffsetDateTime.now().plusHours(1))
        given { certProperties2.expiresOn }.willReturn(OffsetDateTime.now().minusHours(1))

        given { certClient.listPropertiesOfCertificateVersions(any()) }
            .willReturn(
                azureTestUtils.getCertificatePropertiesPagedFlux(
                    listOf(certProperties1, certProperties2)
                )
            )

        given { certClient.getCertificateVersion(anyString(), anyOrNull()) }
            .willReturn(Mono.just(keyVaultCertificate))

        StepVerifier.create(securityKeysService.getCerts())
            .expectNext(keyVaultCertificate)
            .verifyComplete()
        verify(certClient, times(1)).getCertificateVersion(any(), anyOrNull())
    }

    @Test
    fun `Should get all certificates that do not throw error`() = runTest {
        // pre-conditions
        val certProperties1 = mock(CertificateProperties::class.java)
        val certProperties2 = mock(CertificateProperties::class.java)
        val keyVaultCertificate = mock(KeyVaultCertificate::class.java)
        given { certProperties1.isEnabled }.willReturn(true)
        given { certProperties2.isEnabled }.willReturn(true)
        given { certProperties1.expiresOn }.willReturn(OffsetDateTime.now().plusHours(1))
        given { certProperties2.expiresOn }.willReturn(OffsetDateTime.now().plusHours(1))

        given { certClient.listPropertiesOfCertificateVersions(any()) }
            .willReturn(
                azureTestUtils.getCertificatePropertiesPagedFlux(
                    listOf(certProperties1, certProperties2)
                )
            )

        given { certClient.getCertificateVersion(anyString(), anyOrNull()) }
            .willReturn(Mono.error(RuntimeException("test error")))
            .willReturn(Mono.just(keyVaultCertificate))

        StepVerifier.create(securityKeysService.getCerts())
            .expectNext(keyVaultCertificate)
            .verifyComplete()
        verify(certClient, times(2)).getCertificateVersion(any(), anyOrNull())
    }

    @Test
    fun `Should get key store successfully`() = runTest {
        // pre-conditions
        val keyPair = getKeyPairEC()
        val keyStore =
            getKeyStoreWithPKCS12Certificate("testAlias", keyPair, azureSecretConfig.password)
        val secretTest =
            KeyVaultSecret(
                "testName",
                generatePKCS12CertificateAsBase64(keyStore, azureSecretConfig.password),
            )
        given { secretClient.getSecret(any()) }.willReturn(Mono.just(secretTest))

        val obtainedKeyStore = securityKeysService.getKeyStore().block()
        assertThat(keyStore.getKey("testAlias", azureSecretConfig.password.toCharArray()).encoded)
            .isEqualTo(
                obtainedKeyStore
                    ?.getKey("testAlias", azureSecretConfig.password.toCharArray())
                    ?.encoded
            )
        assertThat(keyStore.getCertificate("testAlias").publicKey.encoded)
            .isEqualTo(obtainedKeyStore?.getCertificate("testAlias")?.publicKey?.encoded)
        assertThat(keyStore.aliases().toList())
            .containsExactlyInAnyOrderElementsOf(obtainedKeyStore?.aliases()?.toList())
    }

    @Test
    fun `Should get private key successfully`() = runTest {
        // pre-conditions
        val keyPair = getKeyPairEC()
        val keyStore =
            getKeyStoreWithPKCS12Certificate("testAlias", keyPair, azureSecretConfig.password)
        val secretTest =
            KeyVaultSecret(
                "testName",
                generatePKCS12CertificateAsBase64(keyStore, azureSecretConfig.password),
            )
        val privateKeyWithKid =
            PrivateKeyWithKid(
                getKid(keyStore.getCertificate(keyStore.aliases().nextElement()).encoded),
                keyPair.private,
            )
        given { secretClient.getSecret(any()) }.willReturn(Mono.just(secretTest))

        StepVerifier.create(securityKeysService.getPrivate())
            .expectNext(privateKeyWithKid)
            .verifyComplete()

        verify(secretClient, times(1)).getSecret(any())
    }

    @Test
    fun `Should get public key successfully`() = runTest {
        // pre-conditions
        val keyPair1 = getKeyPairEC()
        val keyPair2 = getKeyPairEC()
        val certificate1 = generatePKCS12Certificate(keyPair1)
        val certificate2 = generatePKCS12Certificate(keyPair2)
        val publicKeyWithKid1 =
            PublicKeyWithKid(getKid(certificate1.encoded), certificate1.publicKey)
        val publicKeyWithKid2 =
            PublicKeyWithKid(getKid(certificate2.encoded), certificate2.publicKey)
        val certProperties1 = mock(CertificateProperties::class.java)
        val certProperties2 = mock(CertificateProperties::class.java)
        val keyVaultCertificate = mock(KeyVaultCertificate::class.java)
        val keyVaultCertificate2 = mock(KeyVaultCertificate::class.java)
        given { certProperties1.isEnabled }.willReturn(true)
        given { certProperties2.isEnabled }.willReturn(true)
        given { certProperties1.expiresOn }.willReturn(OffsetDateTime.now().plusHours(1))
        given { certProperties2.expiresOn }.willReturn(OffsetDateTime.now().plusHours(1))
        given { keyVaultCertificate.cer }.willReturn(certificate1.encoded)
        given { keyVaultCertificate2.cer }.willReturn(certificate2.encoded)

        given { certClient.listPropertiesOfCertificateVersions(any()) }
            .willReturn(
                azureTestUtils.getCertificatePropertiesPagedFlux(
                    listOf(certProperties1, certProperties2)
                )
            )

        given { certClient.getCertificateVersion(anyString(), anyOrNull()) }
            .willReturn(Mono.just(keyVaultCertificate), Mono.just(keyVaultCertificate2))

        StepVerifier.create(securityKeysService.getPublic())
            .expectNext(publicKeyWithKid1)
            .expectNext(publicKeyWithKid2)
            .verifyComplete()
    }
}
