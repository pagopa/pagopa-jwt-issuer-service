package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.certificates.CertificateAsyncClient
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CertificateDetailDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CertificatesResponseDto
import it.pagopa.touchpoint.jwtissuerservice.mdcutilities.LogTracingUtils
import java.net.URI
import java.time.Duration
import java.time.OffsetDateTime
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class CertificatesService(private val certClient: CertificateAsyncClient) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun getCertificateByNameAndValidity(
        certificateName: String,
        validForDays: Int,
    ): Mono<CertificatesResponseDto> =
        certClient
            .listPropertiesOfCertificateVersions(certificateName)
            .doOnNext {
                LogTracingUtils.loggerTracingUtils()
                    .dependency(LogTracingUtils.AZURE_KEY_VAULT_DEPENDENCY)
                    .details(
                        mapOf(
                            "name" to it.name,
                            "version" to it.version,
                            "enabled" to it.isEnabled?.toString(),
                            "expires_on" to it.expiresOn?.toString(),
                            "not_before" to it.notBefore?.toString(),
                        )
                    )
                    .success()
                    .logInfo(logger, "Retrieved Certificate Properties")
            }
            .filter {
                it.isEnabled &&
                    (it.expiresOn == null ||
                        it.expiresOn.isAfter(
                            OffsetDateTime.now().plus(Duration.ofDays(validForDays.toLong()))
                        ))
            }
            .flatMap {
                certClient
                    .getCertificateVersion(certificateName, it.version)
                    .doOnNext { cert ->
                        LogTracingUtils.loggerTracingUtils()
                            .dependency(LogTracingUtils.AZURE_KEY_VAULT_DEPENDENCY)
                            .details(
                                mapOf("name" to cert.name, "version" to cert.properties?.version)
                            )
                            .success()
                            .logInfo(logger, "Retrieved Certificate Version")
                    }
                    .onErrorResume { exception ->
                        LogTracingUtils.loggerTracingUtils()
                            .failure()
                            .logError(logger, exception, "Failed to retrieve certificate version")
                        Mono.empty()
                    }
            }
            .map {
                CertificateDetailDto(
                    name = it.name,
                    expirationDate = it.properties.expiresOn,
                    updated = it.properties.updatedOn,
                    notBefore = it.properties.notBefore,
                    id = URI(it.properties.id),
                )
            }
            .collectList()
            .map { CertificatesResponseDto(certificates = it) }
}
