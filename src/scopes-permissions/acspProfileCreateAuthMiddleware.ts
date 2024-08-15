import {NextFunction, Request, RequestHandler, Response} from 'express'
import {AuthOptions} from '../'
import {authMiddlewareHelper} from '../private-helpers/authMiddlewareHelper'
import { logger } from '../private-helpers/createLogger';
import { RequestScopeAndPermissions } from '../private-helpers/RequestScopeAndPermissions';


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

  logger.debug("Auth acspProfileCreate")

  return authMiddlewareHelper(authMiddlewareConfig, acspProfileCreateRequestScopeAndPermissions)(req, res, next);

}
