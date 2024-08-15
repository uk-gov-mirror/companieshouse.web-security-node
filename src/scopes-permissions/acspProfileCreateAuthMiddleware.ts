import {AuthOptions} from '../'
import {authMiddlewareHelper} from '../private-helpers/authMiddlewareHelper'
import { RequestScopeAndPermissions } from 'app/private-helpers/RequestScopeAndPermissions';
import {NextFunction, Request, RequestHandler, Response} from 'express'

export const acspProfileCreateAuthMiddleware = (options: AuthOptions): RequestHandler => (
  req: Request,
  res: Response,
  next: NextFunction
) => {

  const authMiddlewareConfig: AuthOptions = {
    chsWebUrl: options.chsWebUrl,
    returnUrl: options.returnUrl,
  };

  const acspProfileCreateRequestScopeAndPermissions: RequestScopeAndPermissions = {
    scope: 'https://identity.company-information.service.gov.uk/acsp-profile.create',
    tokenPermissions: {
      'acsp_profile': 'create'
    }
  }

  return authMiddlewareHelper(authMiddlewareConfig, acspProfileCreateRequestScopeAndPermissions)(req, res, next);

}
