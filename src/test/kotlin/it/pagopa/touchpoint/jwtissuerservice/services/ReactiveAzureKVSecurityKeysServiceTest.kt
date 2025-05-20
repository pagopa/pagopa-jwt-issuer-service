package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.certificates.CertificateAsyncClient
import com.azure.security.keyvault.certificates.models.CertificateProperties
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate
import com.azure.security.keyvault.secrets.SecretAsyncClient
import com.azure.security.keyvault.secrets.models.KeyVaultSecret
import it.pagopa.touchpoint.jwtissuerservice.config.properties.AzureSecretConfigProperties
import it.pagopa.touchpoint.jwtissuerservice.utils.AzureTestUtils
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.*
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
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
    fun `Should get key store successfully`() = runTest {
        // pre-conditions
        val keyPair = getKeyPair()
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
        val keyPair = getKeyPair()
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
    }

    @Test
    fun `Should get public key successfully`() = runTest {
        // pre-conditions
        val keyPair1 = getKeyPair()
        val keyPair2 = getKeyPair()
        val certificate1 = generatePKCS12Certificate(keyPair1)
        val certificate2 = generatePKCS12Certificate(keyPair2)
        val certProperties1 = mock(CertificateProperties::class.java)
        val certProperties2 = mock(CertificateProperties::class.java)
        val keyVaultCertificate = mock(KeyVaultCertificate::class.java)
        val keyVaultCertificate2 = mock(KeyVaultCertificate::class.java)
        given { certProperties1.isEnabled }.willReturn(true)
        given { certProperties2.isEnabled }.willReturn(true)
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
            .expectNext(certificate1.publicKey)
            .expectNext(certificate2.publicKey)
            .verifyComplete()
    }

    private fun generatePKCS12Certificate(keyPair: KeyPair): X509Certificate {

        val startDate = Date()
        val endDate = Calendar.getInstance().apply { add(Calendar.YEAR, 1) }.time

        val certBuilder =
            JcaX509v3CertificateBuilder(
                X500Name("CN=Test Certificate"),
                BigInteger.valueOf(System.currentTimeMillis()),
                startDate,
                endDate,
                X500Name("CN=Test Certificate"),
                keyPair.public,
            )

        val contentSigner =
            JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.private)
        val certHolder: X509CertificateHolder = certBuilder.build(contentSigner)
        val certificate: X509Certificate =
            JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider())
                .getCertificate(certHolder)

        return certificate
    }

    private fun getKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        return keyPairGenerator.generateKeyPair()
    }

    private fun getKeyStoreWithPKCS12Certificate(
        alias: String,
        keyPair: KeyPair,
        password: String,
    ): KeyStore {
        val certificate = this.generatePKCS12Certificate(keyPair)

        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(null, null)
        keyStore.setKeyEntry(alias, keyPair.private, password.toCharArray(), arrayOf(certificate))

        return keyStore
    }

    private fun generatePKCS12CertificateAsBase64(keyStore: KeyStore, password: String): String {
        val byteArrayOutputStream = ByteArrayOutputStream()
        keyStore.store(byteArrayOutputStream, password.toCharArray())
        val keyStoreBytes = byteArrayOutputStream.toByteArray()

        return Base64.getEncoder().encodeToString(keyStoreBytes)
    }
}
