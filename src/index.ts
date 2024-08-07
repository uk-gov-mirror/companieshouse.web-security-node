import '@companieshouse/node-session-handler'
import {SessionKey} from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import {SignInInfoKeys} from '@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys'
import {ISignInInfo, IUserProfile} from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import {UserProfileKeys} from '@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys'
import {createLogger} from '@companieshouse/structured-logging-node'
import {NextFunction, Request, RequestHandler, Response} from 'express'

export * from './csrf-protection'


const APP_NAME = 'web-security-node'
const logger = createLogger(APP_NAME)

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

  if (!signedIn) {
    logger.info(`${appName} - handler: userId=${userId}, Not signed in... Redirecting to: ${redirectURI}`)
    return res.redirect(redirectURI)
  }
  else {
    if(options.requestScopeAndPermissions && additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile)) {
      redirectURI = redirectURI.concat(`&additional_scope=${options.requestScopeAndPermissions.scope}`)
    }
  }

  if (options.companyNumber && !isAuthorisedForCompany(options.companyNumber, signInInfo)) {
    logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.companyNumber}... Redirecting to: ${redirectURI}`)
    return res.redirect(redirectURI)
  }

  logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`)
  return next()
}

function isAuthorisedForCompany(companyNumber: string, signInInfo: ISignInInfo): boolean {
  const authorisedCompany = signInInfo[SignInInfoKeys.CompanyNumber]
  if (!authorisedCompany) {
    return false
  }

  return authorisedCompany.localeCompare(companyNumber) === 0
}

// return TRUE if
//   (1) any key in requestScopeAndPermissions.tokenPermissions object is missing from userProfile.tokenPermissions object, OR
//   (2) a value of a key in requestScopeAndPermissions.tokenPermissions object is not in the corresponding value of the same
//       key in userProfile.tokenPermissions
// note for (2) we would need to map values "create,update,etc" => "create", "update", "etc" to get individual values
function additionalScopeIsRequired(requestScopeAndPermissions: RequestScopeAndPermissions, userProfile: IUserProfile): boolean {
  const userTokenPermissions = userProfile[UserProfileKeys.TokenPermissions];

  if (!userTokenPermissions) {
    return false; // should this not return true? if userTokenPermissions is undefined,
                  // then we still need to add the requested permission key(s) & associated scopes?
  }

  for (const key in requestScopeAndPermissions.tokenPermissions) {
    if (!userTokenPermissions.hasOwnProperty(key)) { // e.g. { key1: 'value' }.hasOwnProperty('key1') will return true
      return true; // key is missing in userProfile, so since we request this permission we will need to add it?
    }

    const requestValue = requestScopeAndPermissions.tokenPermissions[key];
    const userValue = userTokenPermissions[key];

    // split, sort, and join the values to compare them irrespective of order
    const requestArray = requestValue.split(',').map(item => item.trim()).sort();
    const userArray = userValue.split(',').map(item => item.trim()).sort();

    if (requestArray.join(',') !== userArray.join(',')) {
      return true; // values differ
    }
  }

  return false;
}
