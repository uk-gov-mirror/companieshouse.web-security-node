import { ErrorRequestHandler, NextFunction, Request, Response } from 'express';
import {
    CsrfError
} from './errors'

const DEFAULT_STATUS_CODE = 403;
const DEFAULT_FAILURE_REASON = "CSRF Token Could not be matched";

interface ErrorResponse {
    statusCode?: number;

    failureReason?: string;
}


export interface ResponseMapping {
    SessionUnsetError?: ErrorResponse;
    MissingCsrfSessionToken?: ErrorResponse;
    CsrfTokensMismatchError?: ErrorResponse;
    CsrfError?: ErrorResponse
}

export interface CsrfErrorHandlerOptions {
    responseMappings?: ResponseMapping;

    defaultStatusCode?: number;

    defaultFailureReason?: string;
}

export const CsrfFailureErrorHandler: (csrfErrorHandlerOpts?: CsrfErrorHandlerOptions) => ErrorRequestHandler = (csrfErrorHandlerOpts?: CsrfErrorHandlerOptions) =>  (err: CsrfError | Error, _: Request, res: Response, next: NextFunction) => {
    csrfErrorHandlerOpts = csrfErrorHandlerOpts || {};
    if (err instanceof CsrfError) {
        let statusCode = DEFAULT_STATUS_CODE;
        let errorBody = DEFAULT_FAILURE_REASON;

        if (csrfErrorHandlerOpts.defaultStatusCode) {
            statusCode = csrfErrorHandlerOpts.defaultStatusCode;
        }

        if (csrfErrorHandlerOpts.defaultFailureReason) {
            errorBody = csrfErrorHandlerOpts.defaultFailureReason
        }

        if (csrfErrorHandlerOpts && csrfErrorHandlerOpts.responseMappings) {
            const responseDetails = Object.keys(csrfErrorHandlerOpts.responseMappings).includes(err.constructor.name)
                // @ts-expect-error Typescript is does not understand the full type
                ? csrfErrorHandlerOpts.responseMappings[err.constructor.name as string]
                : undefined;

            if (responseDetails) {
                if (responseDetails.statusCode) {
                    statusCode = responseDetails.statusCode;
                }

                if (responseDetails.failureReason) {
                    errorBody = responseDetails.failureReason
                }
            }
        }

        return res.status(statusCode).send(errorBody);
    } else {
        return next(err);
    }
}
