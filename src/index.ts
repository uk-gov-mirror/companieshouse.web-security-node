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
export function additionalScopeIsRequired(requestScopeAndPermissions: RequestScopeAndPermissions | undefined | null, userProfile: IUserProfile): boolean {

  // user has not specified any scopes
  if (!requestScopeAndPermissions) {
    return false;
  }

  if (!userProfile.hasOwnProperty(UserProfileKeys.TokenPermissions)) {
    return true;
  }

  const userProfileTokenPermissions = userProfile[UserProfileKeys.TokenPermissions];

  // belt and braces
  if (!userProfileTokenPermissions) {
    return true;
  }

  // check each requested key is in the user profile
  for (const key in requestScopeAndPermissions.tokenPermissions) {

    if (!userProfileTokenPermissions.hasOwnProperty(key)) {
      return true; // key is missing in userProfile, so since we request this permission we will need to add it
    }

    const requestValue = requestScopeAndPermissions.tokenPermissions[key];
    const userProfileValue = userProfileTokenPermissions[key];

    // split, sort, and join the values to compare them irrespective of order
    const normaliseCommaSeparatedString = (value: string): string => {
      return value
        .split(',')                     // Split the string by commas
        .map(item => item.trim())       // Trim whitespace from each item
        .filter(item => item !== '')    // Remove any empty strings
        .sort()                         // Sort the array alphabetically
        .join(',');                     // Join the array back into a string
  };

    const requestArray = normaliseCommaSeparatedString(requestValue);
    const userProfileArray = normaliseCommaSeparatedString(userProfileValue);

    if ( ! userProfileArray.includes(requestArray)) {
      return true; // user profile does not have all the permissions for the requested key
    }
  }

  return false;
}
