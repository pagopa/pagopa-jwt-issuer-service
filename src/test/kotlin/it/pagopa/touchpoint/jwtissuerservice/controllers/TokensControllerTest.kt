package it.pagopa.touchpoint.jwtissuerservice.controllers

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenRequestDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKSResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.ProblemJsonDto
import it.pagopa.touchpoint.jwtissuerservice.services.TokensService
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.given
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest
import org.springframework.http.MediaType
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.test.web.reactive.server.WebTestClient

@WebFluxTest(TokensController::class)
@TestPropertySource(locations = ["classpath:application.test.properties"])
class TokensControllerTest {

    @Autowired lateinit var webClient: WebTestClient
    @MockitoBean private val tokensService: TokensService = mock()

    @Test
    fun `Should generate token successfully`() = runTest {
        // pre-conditions
        val createTokenRequestDto =
            CreateTokenRequestDto(
                audience = "audience",
                duration = 10,
                privateClaims = mapOf("key" to "value"),
            )
        val createTokenResponseDto = CreateTokenResponseDto(token = "token")

        given(tokensService.generateToken(any())).willReturn(createTokenResponseDto)
        webClient
            .post()
            .uri("/tokens")
            .bodyValue(createTokenRequestDto)
            .exchange()
            .expectStatus()
            .isOk
            .expectBody(CreateTokenResponseDto::class.java)
            .consumeWith { assertEquals(createTokenResponseDto, it.responseBody) }
        verify(tokensService, times(1)).generateToken(createTokenRequestDto)
    }

    @Test
    fun `Should return bad request for invalid request`() = runTest {
        // pre-conditions
        val expectedErrorResponse =
            ProblemJsonDto(
                title = "Bad request",
                status = 400,
                detail = "Input request is not valid",
            )
        webClient
            .post()
            .uri("/tokens")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{}")
            .exchange()
            .expectStatus()
            .isBadRequest
            .expectBody(ProblemJsonDto::class.java)
            .consumeWith { assertEquals(expectedErrorResponse, it.responseBody) }
        verify(tokensService, times(0)).generateToken(any())
    }

    @Test
    fun `Should return internal server error for error generating token`() = runTest {
        // pre-conditions
        val createTokenRequestDto =
            CreateTokenRequestDto(
                audience = "audience",
                duration = 10,
                privateClaims = mapOf("key" to "value"),
            )
        val expectedErrorResponse =
            ProblemJsonDto(
                title = "Internal Server Error",
                status = 500,
                detail = "An unexpected error occurred processing the request",
            )
        given(tokensService.generateToken(any()))
            .willThrow(RuntimeException("Error generating token"))
        webClient
            .post()
            .uri("/tokens")
            .bodyValue(createTokenRequestDto)
            .exchange()
            .expectStatus()
            .isEqualTo(500)
            .expectBody(ProblemJsonDto::class.java)
            .consumeWith { assertEquals(expectedErrorResponse, it.responseBody) }
        verify(tokensService, times(1)).generateToken(createTokenRequestDto)
    }

    @Test
    fun `Should return JWKS keys successfully`() = runTest {
        // pre-conditions
        val jwksResponse =
            JWKSResponseDto(
                propertyKeys =
                    listOf(
                        JWKResponseDto(
                            alg = "alg",
                            kty = JWKResponseDto.Kty.EC,
                            use = "use",
                            x = "x",
                            y = "y",
                            kid = "kid",
                            crv = "crv",
                        )
                    )
            )

        given(tokensService.getJwksKeys()).willReturn(jwksResponse)
        webClient
            .get()
            .uri("/tokens/keys")
            .exchange()
            .expectStatus()
            .isOk
            .expectBody(JWKSResponseDto::class.java)
            .consumeWith { assertEquals(jwksResponse, it.responseBody) }
        verify(tokensService, times(1)).getJwksKeys()
    }
}
