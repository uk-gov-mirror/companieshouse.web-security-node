import { NextFunction, Request, RequestHandler, Response } from 'express'
import { AuthOptions } from '..'
import { getAcspManageUserScopesAndPermissions } from '../private-helpers/acspManageUsersScopesAndPermissions'
import { authMiddlewareHelper } from '../private-helpers/authMiddlewareHelper'
import { logger, LOG_MESSAGE_APP_NAME } from '../private-helpers/createLogger'

export const UserRoles = {
    OWNER : 'owner',
    ADMIN : 'admin',
    STANDARD : 'standard'
} as const

export type UserRole = (typeof UserRoles)[keyof typeof UserRoles];

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
    }

    if (!acspOptions.acspNumber?.length || acspOptions.acspNumber === 'undefined') {
        logger.error(`${LOG_MESSAGE_APP_NAME} - acspManageUsersAuthMiddleware: Acsp Number invalid`)
        throw new Error('invalid ACSP number')
    }
    logger.debug(`${LOG_MESSAGE_APP_NAME} - Auth acspManageUsers`)

    return authMiddlewareHelper(authMiddlewareConfig, getAcspManageUserScopesAndPermissions(acspOptions))(req, res, next)
}
