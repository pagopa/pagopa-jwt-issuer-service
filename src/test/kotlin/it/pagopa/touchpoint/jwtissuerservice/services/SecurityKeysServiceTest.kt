package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.secrets.SecretAsyncClient
import com.azure.security.keyvault.secrets.models.KeyVaultSecret
import it.pagopa.touchpoint.jwtissuerservice.config.properties.AzureSecretConfigProperties
import java.io.ByteArrayOutputStream
import java.math.BigInteger
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
import org.mockito.Mockito.mock
import org.mockito.kotlin.any
import org.mockito.kotlin.given
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import reactor.core.publisher.Mono

class SecurityKeysServiceTest {
    private val secretClient: SecretAsyncClient = mock()
    private val azureSecretConfig: AzureSecretConfigProperties =
        AzureSecretConfigProperties(name = "testName", password = "testPassword")
    private val securityKeysService =
        SecurityKeysService(secretClient = secretClient, azureSecretConfig = azureSecretConfig)

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
    fun `Should get key store successfully`() = runTest {
        // pre-conditions
        val keyStore = generatePKCS12Certificate("testAlias", azureSecretConfig.password)
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
        val keyStore = generatePKCS12Certificate("testAlias", azureSecretConfig.password)
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
        val keyStore = generatePKCS12Certificate("testAlias", azureSecretConfig.password)
        val secretTest =
            KeyVaultSecret(
                "testName",
                generatePKCS12CertificateAsBase64(keyStore, azureSecretConfig.password),
            )
        given { secretClient.getSecret(any()) }.willReturn(Mono.just(secretTest))

        val obtainedKeyStore = securityKeysService.getKeyStore().block()
        assertThat(keyStore.getCertificate("testAlias").publicKey.encoded)
            .isEqualTo(obtainedKeyStore?.getCertificate("testAlias")?.publicKey?.encoded)
    }

    private fun generatePKCS12Certificate(alias: String, password: String): KeyStore {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()

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
