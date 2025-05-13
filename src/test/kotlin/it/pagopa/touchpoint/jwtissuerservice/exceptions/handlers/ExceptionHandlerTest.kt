package it.pagopa.touchpoint.jwtissuerservice.exceptions.handlers

import it.pagopa.touchpoint.jwtissuerservice.exceptions.ApiError
import it.pagopa.touchpoint.jwtissuerservice.exceptions.RestApiException
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.kotlin.times
import org.springframework.http.HttpStatus

class ExceptionHandlerTest {

    private val exceptionHandler = ExceptionHandler()

    @Test
    fun `Should map api error errors to problem json response`() {
        // pre-conditions
        class MockException() : ApiError("mock exception") {
            override fun toRestException(): RestApiException =
                RestApiException(
                    httpStatus = HttpStatus.INTERNAL_SERVER_ERROR,
                    title = "Mock exception title",
                    description = "Mock exception description",
                )
        }
        val mockException = MockException()
        // test
        val responseBody = exceptionHandler.handleException(mockException)
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseBody.statusCode)
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), responseBody.body?.status)
        assertEquals("Mock exception title", responseBody.body?.title)
        assertEquals("Mock exception description", responseBody.body?.detail)
    }
}
