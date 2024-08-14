import {AuthOptions} from '../'
import {authMiddlewarePrivate} from '../auth/authMiddlewarePrivate'
import {NextFunction, Request, RequestHandler, Response} from 'express'

export const acspProfileCreateAuthMiddleware = (options: AuthOptions): RequestHandler => (
  req: Request,
  res: Response,
  next: NextFunction
) => {

  const authMiddlewareConfig: AuthOptions = {
    chsWebUrl: options.chsWebUrl,
    returnUrl: options.returnUrl,
    requestScopeAndPermissions: {
      scope: 'https://identity.company-information.service.gov.uk/acsp-profile.create',
      tokenPermissions: {
        'acsp_profile': 'create'
      }
    }
  };

  return authMiddlewarePrivate(authMiddlewareConfig)(req, res, next);
}
