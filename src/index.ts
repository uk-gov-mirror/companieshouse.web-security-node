import '@companieshouse/node-session-handler'
import {SessionKey} from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import {SignInInfoKeys} from '@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys'
import {ISignInInfo, IUserProfile} from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import {createLogger} from '@companieshouse/structured-logging-node'
import {NextFunction, Request, RequestHandler, Response} from 'express'

const APP_NAME = 'web-security-node'
const logger = createLogger(APP_NAME)
const MUTABLE_METHODS = ["POST", "DELETE", "PUT", "PATCH"]

export interface AuthOptions {
  returnUrl: string
  chsWebUrl: string
  companyNumber?: string
}

export interface CsrfOptions {
  enabled: boolean
}

export const authMiddleware = (options: AuthOptions): RequestHandler => (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const appName = 'CH Web Security Node'

  if (!options.chsWebUrl) {
    logger.error(`${appName} - handler: Required Field CHS Web URL not set`)
    throw new Error('Required Field CHS Web URL not set')
  }

  let redirectURI = `${options.chsWebUrl}/signin?return_to=${options.returnUrl}`

  if(options.companyNumber) {
    redirectURI = redirectURI.concat(`&company_number=${options.companyNumber}`)
  }

  if (!req.session) {
    logger.debug(`${appName} - handler: Session object is missing!`)
    return res.redirect(redirectURI)
  }

  const signInInfo: ISignInInfo = req.session.get<ISignInInfo>(SessionKey.SignInInfo) || {}
  const signedIn: boolean = signInInfo![SignInInfoKeys.SignedIn] === 1
  const userProfile: IUserProfile = signInInfo![SignInInfoKeys.UserProfile] || {}
  const userId: string | undefined = userProfile?.id

  if (!signedIn) {
    logger.info(`${appName} - handler: userId=${userId}, Not signed in... Redirecting to: ${redirectURI}`)
    return res.redirect(redirectURI)
  }

  if (options.companyNumber && !isAuthorisedForCompany(options.companyNumber, signInInfo)) {
    logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.companyNumber}... Redirecting to: ${redirectURI}`)
    return res.redirect(redirectURI)
  }

  logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`)
  return next()
}

export const csrfRequestMiddleware = (options: CsrfOptions): RequestHandler => (
  req: Request,
  _: Response,
  next: NextFunction
) => {
  const appName = 'CH Web Security Node'

  if (!options.enabled) {
    console.debug("CSRF protections disabled");
    return next()
  }

  try {
    if (MUTABLE_METHODS.includes(req.method)) {
      const csrfTokenInRequest = req.body["_csrf"] || req.headers["X-CSRF-TOKEN"];

      if (!req.session) {
        logger.debug(`${appName} - handler: Session object is missing!`)
        throw new Error("Session not set.")
      }

      const sessionCsrfToken = req.session.get<string>(SessionKey.CsrfToken);
      console.log(sessionCsrfToken)

      if (csrfTokenInRequest !== sessionCsrfToken) {
        logger.error("Possible csrf attack mitigated");
        throw "Invalid CSRF token.";
      }
    }

    return next()
  } catch (err) {
    logger.errorRequest(req, `Could not handle CSRF validation: ${err}`);
    return next(err);
  }
};

function isAuthorisedForCompany(companyNumber: string, signInInfo: ISignInInfo): boolean {
  const authorisedCompany = signInInfo[SignInInfoKeys.CompanyNumber]
  if (!authorisedCompany) {
    return false
  }

  return authorisedCompany.localeCompare(companyNumber) === 0
}
