package it.pagopa.touchpoint.jwtissuerservice.exceptions.handlers

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.ProblemJsonDto
import it.pagopa.touchpoint.jwtissuerservice.exceptions.ApiError
import it.pagopa.touchpoint.jwtissuerservice.exceptions.RestApiException
import jakarta.validation.ValidationException
import kotlin.jvm.javaClass
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.bind.support.WebExchangeBindException
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException
import org.springframework.web.server.ServerWebInputException

@RestControllerAdvice
class ExceptionHandler {
    private val logger = LoggerFactory.getLogger(javaClass)

    @ExceptionHandler(RestApiException::class)
    fun handleException(e: RestApiException): ResponseEntity<ProblemJsonDto> {
        logger.error("Exception processing request", e)
        return ResponseEntity.status(e.httpStatus)
            .body(
                ProblemJsonDto(
                    status = e.httpStatus.value(),
                    title = e.title,
                    detail = e.description,
                )
            )
    }

    @ExceptionHandler(ApiError::class)
    fun handleException(e: ApiError): ResponseEntity<ProblemJsonDto> {
        return handleException(e.toRestException())
    }

    @ExceptionHandler(Exception::class)
    fun handleGenericException(e: Exception): ResponseEntity<ProblemJsonDto> {
        logger.error("Exception processing the request", e)
        return ResponseEntity.internalServerError()
            .body(
                ProblemJsonDto(
                    status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    title = "Internal Server Error",
                    detail = "An unexpected error occurred processing the request",
                )
            )
    }

    /** Validation request exception handler */
    @ExceptionHandler(
        MethodArgumentNotValidException::class,
        MethodArgumentTypeMismatchException::class,
        ServerWebInputException::class,
        ValidationException::class,
        HttpMessageNotReadableException::class,
        WebExchangeBindException::class,
    )
    fun handleRequestValidationException(e: Exception): ResponseEntity<ProblemJsonDto> {
        logger.error("Input request is not valid", e)
        return ResponseEntity.badRequest()
            .body(
                ProblemJsonDto(
                    status = HttpStatus.BAD_REQUEST.value(),
                    title = "Bad request",
                    detail = "Input request is not valid",
                )
            )
    }
}
