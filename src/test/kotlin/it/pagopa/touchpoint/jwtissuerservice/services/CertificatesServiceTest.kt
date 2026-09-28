package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.certificates.CertificateAsyncClient
import com.azure.security.keyvault.certificates.models.CertificateProperties
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy
import java.net.URI
import java.time.OffsetDateTime
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.kotlin.any
import org.mockito.kotlin.given
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import reactor.core.publisher.Mono

class CertificatesServiceTest {
    private val certClient: CertificateAsyncClient = mock()
    private val certificatesService = CertificatesService(certClient = certClient)
    private val validForDays = 30

    @Test
    fun `Should get certificate detail successfully`() = runTest {
        // pre-conditions
        val certProperties = mock(CertificateProperties::class.java)
        val keyVaultCertificate = mock(KeyVaultCertificateWithPolicy::class.java)
        val certificateId = "https://kv-name.vault.azure.net/secrets/certificate-name/encoded-id"
        val notBefore = OffsetDateTime.now().minusDays(1)
        val updatedOn = OffsetDateTime.now().minusHours(1)
        val expiresOn = OffsetDateTime.now().plusDays(60)
        given { certProperties.isEnabled }.willReturn(true)
        given { certProperties.expiresOn }.willReturn(expiresOn)
        given { certProperties.id }.willReturn(certificateId)
        given { certProperties.notBefore }.willReturn(notBefore)
        given { certProperties.updatedOn }.willReturn(updatedOn)
        given { keyVaultCertificate.name }.willReturn("certificate-name")
        given { keyVaultCertificate.properties }.willReturn(certProperties)

        given { certClient.getCertificate("certificate-name") }
            .willReturn(Mono.just(keyVaultCertificate))

        // test
        val certificateDetail =
            certificatesService
                .getCertificateByNameAndValidity("certificate-name", validForDays)
                .block()

        // assertions
        assertThat(certificateDetail?.name).isEqualTo("certificate-name")
        assertThat(certificateDetail?.expirationDate).isEqualTo(expiresOn)
        assertThat(certificateDetail?.updated).isEqualTo(updatedOn)
        assertThat(certificateDetail?.notBefore).isEqualTo(notBefore)
        assertThat(certificateDetail?.id).isEqualTo(URI(certificateId))
        verify(certClient, times(1)).getCertificate("certificate-name")
    }

    @Test
    fun `Should filter out disabled certificate`() = runTest {
        // pre-conditions
        val certProperties = mock(CertificateProperties::class.java)
        val keyVaultCertificate = mock(KeyVaultCertificateWithPolicy::class.java)
        given { certProperties.isEnabled }.willReturn(false)
        given { keyVaultCertificate.properties }.willReturn(certProperties)

        given { certClient.getCertificate("certificate-name") }
            .willReturn(Mono.just(keyVaultCertificate))

        // test
        val certificateDetail =
            certificatesService
                .getCertificateByNameAndValidity("certificate-name", validForDays)
                .block()

        // assertions
        assertThat(certificateDetail).isNull()
    }

    @Test
    fun `Should filter out certificate that will not be valid for the requested days`() = runTest {
        // pre-conditions
        val certProperties = mock(CertificateProperties::class.java)
        val keyVaultCertificate = mock(KeyVaultCertificateWithPolicy::class.java)
        given { certProperties.isEnabled }.willReturn(true)
        given { certProperties.expiresOn }.willReturn(OffsetDateTime.now().plusDays(1))
        given { keyVaultCertificate.properties }.willReturn(certProperties)

        given { certClient.getCertificate("certificate-name") }
            .willReturn(Mono.just(keyVaultCertificate))

        // test
        val certificateDetail =
            certificatesService
                .getCertificateByNameAndValidity("certificate-name", validForDays)
                .block()

        // assertions
        assertThat(certificateDetail).isNull()
    }

    @Test
    fun `Should return empty when no certificate is found`() = runTest {
        // pre-conditions
        given { certClient.getCertificate("certificate-name") }.willReturn(Mono.empty())

        // test
        val certificateDetail =
            certificatesService
                .getCertificateByNameAndValidity("certificate-name", validForDays)
                .block()

        // assertions
        assertThat(certificateDetail).isNull()
        verify(certClient, times(1)).getCertificate(any())
    }
}
