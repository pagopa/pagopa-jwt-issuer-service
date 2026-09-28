package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.certificates.CertificateAsyncClient
import com.azure.security.keyvault.certificates.models.CertificateProperties
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate
import it.pagopa.touchpoint.jwtissuerservice.utils.AzureTestUtils
import java.net.URI
import java.time.OffsetDateTime
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.mock
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.given
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import reactor.core.publisher.Mono

class CertificatesServiceTest {
    private val azureTestUtils: AzureTestUtils = AzureTestUtils()
    private val certClient: CertificateAsyncClient = mock()
    private val certificatesService = CertificatesService(certClient = certClient)
    private val validForDays = 30

    @Test
    fun `Should get certificate detail successfully`() = runTest {
        // pre-conditions
        val certProperties = mock(CertificateProperties::class.java)
        val keyVaultCertificate = mock(KeyVaultCertificate::class.java)
        val certificateId = "https://kv-name.vault.azure.net/secrets/certificate-name/encoded-id"
        val notBefore = OffsetDateTime.now().minusDays(1)
        val updatedOn = OffsetDateTime.now().minusHours(1)
        val expiresOn = OffsetDateTime.now().plusDays(60)
        given { certProperties.isEnabled }.willReturn(true)
        given { certProperties.expiresOn }.willReturn(expiresOn)
        given { certProperties.version }.willReturn("version1")
        given { certProperties.id }.willReturn(certificateId)
        given { certProperties.notBefore }.willReturn(notBefore)
        given { certProperties.updatedOn }.willReturn(updatedOn)
        given { keyVaultCertificate.name }.willReturn("certificate-name")
        given { keyVaultCertificate.properties }.willReturn(certProperties)

        given { certClient.listPropertiesOfCertificateVersions(any()) }
            .willReturn(azureTestUtils.getCertificatePropertiesPagedFlux(listOf(certProperties)))
        given { certClient.getCertificateVersion(anyString(), anyOrNull()) }
            .willReturn(Mono.just(keyVaultCertificate))

        // test
        val response =
            certificatesService
                .getCertificateByNameAndValidity("certificate-name", validForDays)
                .block()

        // assertions
        assertThat(response?.certificates).hasSize(1)
        val certificateDetail = response?.certificates?.first()
        assertThat(certificateDetail?.name).isEqualTo("certificate-name")
        assertThat(certificateDetail?.expirationDate).isEqualTo(expiresOn)
        assertThat(certificateDetail?.updated).isEqualTo(updatedOn)
        assertThat(certificateDetail?.notBefore).isEqualTo(notBefore)
        assertThat(certificateDetail?.id).isEqualTo(URI(certificateId))
        verify(certClient, times(1)).getCertificateVersion("certificate-name", "version1")
    }

    @Test
    fun `Should filter out disabled certificate versions`() = runTest {
        // pre-conditions
        val certProperties = mock(CertificateProperties::class.java)
        given { certProperties.isEnabled }.willReturn(false)

        given { certClient.listPropertiesOfCertificateVersions(any()) }
            .willReturn(azureTestUtils.getCertificatePropertiesPagedFlux(listOf(certProperties)))

        // test
        val response =
            certificatesService
                .getCertificateByNameAndValidity("certificate-name", validForDays)
                .block()

        // assertions
        assertThat(response?.certificates).isEmpty()
        verify(certClient, times(0)).getCertificateVersion(any(), anyOrNull())
    }

    @Test
    fun `Should filter out certificate versions that will not be valid for the requested days`() =
        runTest {
            // pre-conditions
            val certProperties = mock(CertificateProperties::class.java)
            given { certProperties.isEnabled }.willReturn(true)
            given { certProperties.expiresOn }.willReturn(OffsetDateTime.now().plusDays(1))

            given { certClient.listPropertiesOfCertificateVersions(any()) }
                .willReturn(
                    azureTestUtils.getCertificatePropertiesPagedFlux(listOf(certProperties))
                )

            // test
            val response =
                certificatesService
                    .getCertificateByNameAndValidity("certificate-name", validForDays)
                    .block()

            // assertions
            assertThat(response?.certificates).isEmpty()
            verify(certClient, times(0)).getCertificateVersion(any(), anyOrNull())
        }

    @Test
    fun `Should let a version with no expiration date through the validity filter`() = runTest {
        // pre-conditions
        val certProperties = mock(CertificateProperties::class.java)
        given { certProperties.isEnabled }.willReturn(true)
        given { certProperties.expiresOn }.willReturn(null)
        given { certProperties.version }.willReturn("version1")

        given { certClient.listPropertiesOfCertificateVersions(any()) }
            .willReturn(azureTestUtils.getCertificatePropertiesPagedFlux(listOf(certProperties)))
        given { certClient.getCertificateVersion(anyString(), anyOrNull()) }
            .willReturn(Mono.empty())

        // test
        val response =
            certificatesService
                .getCertificateByNameAndValidity("certificate-name", validForDays)
                .block()

        // assertions: the version passes the filter, triggering the version fetch,
        // even though no result is emitted here
        assertThat(response?.certificates).isEmpty()
        verify(certClient, times(1)).getCertificateVersion("certificate-name", "version1")
    }

    @Test
    fun `Should skip certificate versions for which retrieval fails and continue processing the others`() =
        runTest {
            // pre-conditions
            val certProperties1 = mock(CertificateProperties::class.java)
            val certProperties2 = mock(CertificateProperties::class.java)
            val keyVaultCertificate = mock(KeyVaultCertificate::class.java)
            given { certProperties1.isEnabled }.willReturn(true)
            given { certProperties2.isEnabled }.willReturn(true)
            given { certProperties1.expiresOn }.willReturn(OffsetDateTime.now().plusDays(60))
            given { certProperties2.expiresOn }.willReturn(OffsetDateTime.now().plusDays(60))
            given { certProperties1.version }.willReturn("version1")
            given { certProperties2.version }.willReturn("version2")
            given { certProperties2.id }.willReturn("https://kv-name.vault.azure.net/id")
            given { certProperties2.notBefore }.willReturn(OffsetDateTime.now())
            given { certProperties2.updatedOn }.willReturn(OffsetDateTime.now())
            given { keyVaultCertificate.name }.willReturn("certificate-name")
            given { keyVaultCertificate.properties }.willReturn(certProperties2)

            given { certClient.listPropertiesOfCertificateVersions(any()) }
                .willReturn(
                    azureTestUtils.getCertificatePropertiesPagedFlux(
                        listOf(certProperties1, certProperties2)
                    )
                )
            given { certClient.getCertificateVersion(anyString(), anyOrNull()) }
                .willReturn(
                    Mono.error(RuntimeException("test error")),
                    Mono.just(keyVaultCertificate),
                )

            // test
            val response =
                certificatesService
                    .getCertificateByNameAndValidity("certificate-name", validForDays)
                    .block()

            // assertions
            assertThat(response?.certificates).hasSize(1)
            verify(certClient, times(2)).getCertificateVersion(any(), anyOrNull())
        }

    @Test
    fun `Should return empty certificates list when no certificate version is found`() = runTest {
        // pre-conditions
        given { certClient.listPropertiesOfCertificateVersions(any()) }
            .willReturn(azureTestUtils.getCertificatePropertiesPagedFlux(emptyList()))

        // test
        val response =
            certificatesService
                .getCertificateByNameAndValidity("certificate-name", validForDays)
                .block()

        // assertions
        assertThat(response?.certificates).isEmpty()
        verify(certClient, times(0)).getCertificateVersion(any(), anyOrNull())
    }
}
