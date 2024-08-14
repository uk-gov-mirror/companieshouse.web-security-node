import '@companieshouse/node-session-handler'
import {IUserProfile} from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import {UserProfileKeys} from '@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys'
import {NextFunction, Request, RequestHandler, Response} from 'express'
import {authMiddlewarePrivate} from './auth/authMiddlewarePrivate'

export * from './csrf-protection'
export * from './scopes-permissions'
export * from './utils'


export interface AuthOptions {
  returnUrl: string
  chsWebUrl: string
  companyNumber?: string
  requestScopeAndPermissions?: RequestScopeAndPermissions
}

export interface RequestScopeAndPermissions {
  scope: string
  tokenPermissions: IUserProfile[UserProfileKeys.TokenPermissions] // { [permission: string]: string }
}

/*
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

  if ( ! req.session)  {
    if(options.requestScopeAndPermissions) {
      redirectURI = redirectURI.concat(`&additional_scope=${options.requestScopeAndPermissions.scope}`)
    }

    logger.debug(`${appName} - handler: Session object is missing!`)
    return res.redirect(redirectURI)
  }

  const signInInfo: ISignInInfo = req.session.get<ISignInInfo>(SessionKey.SignInInfo) || {}
  const signedIn: boolean = signInInfo![SignInInfoKeys.SignedIn] === 1
  const userProfile: IUserProfile = signInInfo![SignInInfoKeys.UserProfile] || {}
  const userId: string | undefined = userProfile?.id

  if (options.requestScopeAndPermissions && additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile)) {
    redirectURI = redirectURI.concat(`&additional_scope=${options.requestScopeAndPermissions.scope}`)
    logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.requestScopeAndPermissions}... Updating URL to: ${redirectURI}`)
  }

  if (!signedIn) {
    logger.info(`${appName} - handler: userId=${userId}, Not signed in... Redirecting to: ${redirectURI}`)
    return res.redirect(redirectURI)
  }

  if (options.companyNumber && !isAuthorisedForCompany(options.companyNumber, signInInfo)) {
    logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.companyNumber}... Redirecting to: ${redirectURI}`)
    return res.redirect(redirectURI)
  }

  if (options.requestScopeAndPermissions && additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile)) {
    logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.requestScopeAndPermissions}... Redirecting to: ${redirectURI}`)
    return res.redirect(redirectURI)
  }

  logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`)
  return next()
}
  */

export const authMiddleware = (options: AuthOptions): RequestHandler => (
  req: Request,
  res: Response,
  next: NextFunction
) => {

  return authMiddlewarePrivate(options)(req, res, next);
}
/*
function isAuthorisedForCompany(companyNumber: string, signInInfo: ISignInInfo): boolean {
  const authorisedCompany = signInInfo[SignInInfoKeys.CompanyNumber]
  if (!authorisedCompany) {
    return false
  }

  return authorisedCompany.localeCompare(companyNumber) === 0
}
  */
