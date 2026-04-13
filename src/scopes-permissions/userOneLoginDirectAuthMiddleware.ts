import { NextFunction, Request, RequestHandler, Response } from 'express'
import { AuthOptions } from '../'
import { RequestScopeAndPermissions } from '../private-helpers/RequestScopeAndPermissions'
import { authMiddlewareHelper } from '../private-helpers/authMiddlewareHelper'
import { logger, LOG_MESSAGE_APP_NAME } from '../private-helpers/createLogger'

export const userOneLoginDirectAuthMiddleware = (options: AuthOptions): RequestHandler => (
    req: Request,
    res: Response,
    next: NextFunction
) => {

    const authMiddlewareConfig: AuthOptions = {
        chsWebUrl: options.chsWebUrl,
        returnUrl: options.returnUrl,
    }

    const oneLoginDirectRequestScopeAndPermissions: RequestScopeAndPermissions = {
        scope: 'https://account.companieshouse.gov.uk/user.write-full https://identity.company-information.service.gov.uk/user/one-login.force.direct',
        tokenPermissions: {
            'one_login': 'read'
        }
    }

    logger.debug(`${LOG_MESSAGE_APP_NAME} - Auth userOneLoginDirect`)

    return authMiddlewareHelper(authMiddlewareConfig, oneLoginDirectRequestScopeAndPermissions)(req, res, next)
}
