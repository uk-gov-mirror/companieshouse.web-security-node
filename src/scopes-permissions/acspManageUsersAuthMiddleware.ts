import { NextFunction, Request, RequestHandler, Response } from 'express'
import { AuthOptions } from '..'
import { authMiddlewareHelper } from '../private-helpers/authMiddlewareHelper'
import { logger, LOG_MESSAGE_APP_NAME } from '../private-helpers/createLogger';
import { getAcspManageUserScopesAndPermissions } from '../private-helpers/acspManageUsersHelper';

export enum UserRole {
    OWNER = "owner",
    ADMIN = "admin",
    STANDARD = "standard"
}

export interface AcspOptions {
    user_role: UserRole,
    acsp_number: string
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

    logger.debug(`${LOG_MESSAGE_APP_NAME} - Auth acspManageUsers`)

    return authMiddlewareHelper(authMiddlewareConfig, getAcspManageUserScopesAndPermissions(acspOptions))(req, res, next);

}
