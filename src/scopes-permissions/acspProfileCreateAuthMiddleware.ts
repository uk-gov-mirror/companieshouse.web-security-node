import {AuthOptions, authMiddleware} from '../'
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

  return authMiddleware(authMiddlewareConfig)(req, res, next);
}
