import { Session, SessionStore } from "@companieshouse/node-session-handler";
import { NextFunction, Request, RequestHandler, Response } from "express";
import { v4 as uuidv4 } from 'uuid';
import expressAsyncHandler from "express-async-handler";
import { SessionKey } from "@companieshouse/node-session-handler/lib/session/keys/SessionKey";
import { createLogger } from "@companieshouse/structured-logging-node";
import { Cookie } from "@companieshouse/node-session-handler/lib/session/model/Cookie";


const APP_NAME = 'web-security-node'
const logger = createLogger(APP_NAME)

const DEFAULT_CSRF_TOKEN_HEADER = "X-CSRF-TOKEN"
const DEFAULT_CSRF_TOKEN_PARAMETER_NAME = "_csrf"
const MUTABLE_METHODS = ['POST', 'DELETE', 'PUT', 'PATCH']
const defaultChsSessionCookieName = "_SID";

export const defaultCsrfTokenFactory = () => uuidv4()

export interface CsrfOptions {
    enabled: boolean
    sessionStore: SessionStore
    sessionCookieName?: string,
    csrfTokenFactory?: () => string,
    createWhenCsrfTokenAbsent?: boolean
    headerName?: string
    parameterName?: string
}

export class CsrfTokensMismatchError extends Error { }

export class MissingCsrfSessionToken extends Error { }

export const CsrfProtectionMiddleware = (csrfOptions: CsrfOptions): RequestHandler => {
    return expressAsyncHandler(csrfFilter(csrfOptions));
}

const csrfFilter = (options: CsrfOptions): RequestHandler => {
    return async (req: Request, res: Response, next: NextFunction): Promise<any> => {
        const appName = 'CH Web Security Node'

        if (!options.enabled) {
            console.debug('CSRF protections disabled')
            return next()
        }

        const headerName = options.headerName || DEFAULT_CSRF_TOKEN_HEADER
        const parameterName = options.parameterName || DEFAULT_CSRF_TOKEN_PARAMETER_NAME
        const csrfTokenFactory = options.csrfTokenFactory || defaultCsrfTokenFactory
        const cookieName = options.sessionCookieName || defaultChsSessionCookieName;

        try {
            if (!req.session) {
                logger.debug(`${appName} - handler: Session object is missing!`)
                throw new Error('Session not set.')
            }

            const sessionCsrfToken = req.session.get<string>(SessionKey.CsrfToken)

            if (MUTABLE_METHODS.includes(req.method)) {
                if (!sessionCsrfToken) {
                    throw new MissingCsrfSessionToken("Session does not include CSRF token.")
                }

                const csrfTokenInRequest = req.body[parameterName] || req.headers[headerName]

                if (csrfTokenInRequest !== sessionCsrfToken) {
                    logger.error('Possible csrf attack mitigated')
                    throw new CsrfTokensMismatchError('Invalid CSRF token.')
                }

                res.render = modifiedRender(res, sessionCsrfToken);
            } else if (
                !sessionCsrfToken && options.createWhenCsrfTokenAbsent !== false) {
                const csrfToken = csrfTokenFactory();
                const newSessionData = {
                    ...(req.session.data),
                    [SessionKey.CsrfToken]: csrfToken
                }

                req.session = new Session(newSessionData);

                await options.sessionStore.store(
                    Cookie.createFrom(req.cookies[cookieName]),
                    newSessionData
                )

                res.render = modifiedRender(res, csrfToken);
            }

            return next();
        } catch (err) {
            logger.errorRequest(req, `Could not handle CSRF validation: ${err}`)
            return next(err)
        }
    }
}

const modifiedRender = (res: Response, csrfToken: string) => {
    const originalRender = res.render;
    return (view: string, parametersOrCallback?: object | ((err: Error, html: string) => void), callback?: (err: Error, html: string) => void) => {
        if (typeof parametersOrCallback === "object") {
            return originalRender(
                view, {
                    ...parametersOrCallback,
                    csrfToken: csrfToken
                },
                callback
            )
        }
        return originalRender(view, parametersOrCallback, callback)
    }
}
