import { NextFunction, Request, RequestHandler, Response } from 'express'
import { AuthOptions } from '..'
import { authMiddlewareHelper } from '../private-helpers/authMiddlewareHelper'
import { logger, LOG_MESSAGE_APP_NAME } from '../private-helpers/createLogger';
import { getAcspManageUserScopesAndPermissions } from '../private-helpers/acspManageUsersScopesAndPermissions';

export enum UserRole {
    OWNER = "owner",
    ADMIN = "admin",
    STANDARD = "standard"
}

export interface AcspOptions {
    userRole?: UserRole,
    acspNumber: string
}

export const acspManageUsersAuthMiddleware = (options: AuthOptions, acspOptions: AcspOptions): RequestHandler => (
    req: Request,
    res: Response,
    next: NextFunction
) => {

    const authMiddlewareConfig: AuthOptions = {
        chsWebUrl: options.chsWebUrl,
        returnUrl: options.returnUrl,
    };

    if (!acspOptions.acspNumber?.length || acspOptions.acspNumber === 'undefined') {
        logger.error(`${LOG_MESSAGE_APP_NAME} - acspManageUsersAuthMiddleware: Acsp Number invalid`)
        throw new Error('invalid ACSP number')
    }
    logger.debug(`${LOG_MESSAGE_APP_NAME} - Auth acspManageUsers`)

    return authMiddlewareHelper(authMiddlewareConfig, getAcspManageUserScopesAndPermissions(acspOptions))(req, res, next);

}
