import { ErrorRequestHandler, NextFunction, Request, Response } from 'express'
import {
    CsrfError
} from './errors'

const DEFAULT_STATUS_CODE = 403
const DEFAULT_FAILURE_REASON = 'CSRF Token Could not be matched'

/**
 * Provides details about the error response for the exception raised
 */
interface ErrorResponse {

    /**
     * The status code returned for the exception
     */
    statusCode?: number

    /**
     * Reason for the error returned in response as the body
     */
    failureReason?: string
}


/**
 * Maps the exception to the response
 */
export interface ResponseMapping {
    SessionUnsetError?: ErrorResponse
    MissingCsrfSessionToken?: ErrorResponse
    CsrfTokensMismatchError?: ErrorResponse
    CsrfError?: ErrorResponse
}

/**
 * Provides the options for the CsrfFailureErrorHandler
 */
export interface CsrfErrorHandlerOptions {
    /**
     * The mappings for any different responses for CSRF failures
     */
    responseMappings?: ResponseMapping

    /**
     * The default status code for failures
     */
    defaultStatusCode?: number

    /**
     * The default failure reason for failure
     */
    defaultFailureReason?: string
}

/**
 * An express error handler which will handle any failures arising from the
 * CSRF middleware. The behaviour is customisable using the options.
 *
 * When not a CSRF error, calls the next function in the chain.
 * @param csrfErrorHandlerOpts Configuration defining the responses from the
 *      error handler when there is a CSRF failure
 * @returns response
 */
export const CsrfFailureErrorHandler: (csrfErrorHandlerOpts?: CsrfErrorHandlerOptions) => ErrorRequestHandler =
    (csrfErrorHandlerOpts: CsrfErrorHandlerOptions = {}) =>
        (err: CsrfError | Error, _: Request, res: Response, next: NextFunction) => {

    // Call next function in chain for any error not CSRF error
    if (!(err instanceof CsrfError)) {
        return next(err)
    }

    // Set the statusCode and errorBody to the correct value according to the
    // defaults either specified in the options or the module defaults
    // (when undefined)
    let statusCode = csrfErrorHandlerOpts.defaultStatusCode || DEFAULT_STATUS_CODE
    let errorBody = csrfErrorHandlerOpts.defaultFailureReason || DEFAULT_FAILURE_REASON

    if (csrfErrorHandlerOpts.responseMappings) {

        // Find the details for the response if defined in the response mappings
        // @ts-expect-error Typescript is does not understand the full type
        const responseDetails = csrfErrorHandlerOpts.responseMappings[err.constructor.name]

        if (responseDetails) {
            // When there are a specific response for a given exception set the
            // status code and body accordingly
            if (responseDetails.statusCode) {
                statusCode = responseDetails.statusCode
            }

            if (responseDetails.failureReason) {
                errorBody = responseDetails.failureReason
            }
        }
    }

    // Respond with the specified information
    return res.status(statusCode).send(errorBody)
}
