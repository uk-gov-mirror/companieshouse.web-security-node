import '@companieshouse/node-session-handler'
import {SessionKey} from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import {SignInInfoKeys} from '@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys'
import {UserProfileKeys} from '@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys'
import {ISignInInfo, IUserProfile} from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import {createLogger} from '@companieshouse/structured-logging-node'
import {NextFunction, Request, RequestHandler, Response} from 'express'

const LEGACY_AUTH_COMPANY_SCOPE = new RegExp('/company/([0-9a-zA-Z]*)$')
const FINE_GRAINED_AUTH_COMPANY_SCOPE = new RegExp('/company/([0-9a-zA-Z]*)/admin.write-full$')

const APP_NAME = 'web-security-node'
const logger = createLogger(APP_NAME)

export interface AuthOptions {
  returnUrl: string
  accountWebUrl: string
  useFineGrainedScopes: boolean
  companyNumber?: string
}

export const authMiddleware = (options: AuthOptions): RequestHandler => (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const appName = 'CH Web Security Node'
  let redirectURI = `${options.accountWebUrl}/signin?return_to=${options.returnUrl}`

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

  if (options.companyNumber && !isAuthorisedForCompany(options.companyNumber, signInInfo, options)) {
    logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.companyNumber}... Redirecting to: ${redirectURI}`)
    return res.redirect(redirectURI)
  }

  logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`)
  next()
}

function isAuthorisedForCompany(companyNumber: string, signInInfo: ISignInInfo, options: AuthOptions): boolean {
  const authorisedCompany = signInInfo[SignInInfoKeys.CompanyNumber]
  if (!authorisedCompany) {
    return false
  }

  const authorisedCompanyIsCorrect: boolean =
    authorisedCompany.localeCompare(companyNumber) === 0

  return authorisedCompanyIsCorrect && hasAuthorisedCompanyScope(companyNumber, signInInfo, options)
}

function hasAuthorisedCompanyScope(companyNumber: string, signInInfo: ISignInInfo, options: AuthOptions): boolean {
  const userProfile: IUserProfile = signInInfo![SignInInfoKeys.UserProfile] || {}
  const scope: string | undefined = userProfile?.[UserProfileKeys.Scope]

  if (!scope) {
    return false
  }

  const scopes: string[] = scope.split(' ')

  for (const singleScope of scopes) {
    const matches = singleScope.match(getAuthCompanyScopePattern(options))
    if (matches && matches[1].localeCompare(companyNumber) === 0) {
      return true
    }
  }

  return false

}

function getAuthCompanyScopePattern(options: AuthOptions): RegExp {
  if (options.useFineGrainedScopes) {
    return FINE_GRAINED_AUTH_COMPANY_SCOPE
  } else {
    return LEGACY_AUTH_COMPANY_SCOPE
  }
}
