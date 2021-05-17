import '@companieshouse/node-session-handler'
import { SessionKey } from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import { SignInInfoKeys } from '@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys'
import { ISignInInfo, IUserProfile } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import { createLogger } from '@companieshouse/structured-logging-node'
import { NextFunction, Request, RequestHandler, Response } from 'express'
import JwtEncryptionService from './encryption/jwt.encryption.service'

const APP_NAME = 'web-security-node'
const logger = createLogger(APP_NAME)

export interface AuthOptions {
  returnUrl: string
  accountWebUrl: string
}

export const authMiddleware = (options: AuthOptions): RequestHandler => (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const appName = 'CH Web Security Node'
  const redirectURI = `${options.accountWebUrl}/signin?return_to=${options.returnUrl}`

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

  logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`)
  next()
}

const LEGACY_COMPANY_SCOPE_PREFIX = 'https://api.companieshouse.gov.uk/company/'
const SCOPE_USER_WRITE_FULL = 'https://account.companieshouse.gov.uk/user.write-full'
const SCOPE_COMPANY_WRITE_FULL_FORMAT = 'https://api.companieshouse.gov.uk/company/{COMPANY_NUMBER}/admin.write-full'

export interface CompanyAuthConfig {
  authUri: string,
  companyNumber: string
  accountRequestKey: string,
  accountClientId: string,
  callbackUri: string,
  useFineGrainScopesModel: string
}

export const companyAuthMiddleware = (config: CompanyAuthConfig): RequestHandler => async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
  const appName = 'CH Web Security Node'

  if (!req.session) {
    logger.debug(`${appName} - handler: Session object is missing!`)
    throw new Error('Session object is missing for Company Auth Middleware')
  }

  const signInInfo: ISignInInfo = req.session.get<ISignInInfo>(SessionKey.SignInInfo) || {}

  const companyNumber = config.companyNumber
  let scope

  if (companyNumber) {
    scope = createScope(companyNumber, config)
  }

  if (signInInfo[SignInInfoKeys.CompanyNumber] === companyNumber) {
    logger.debug(`${appName} - handler: User already authenticated for company`)
    return next()
  }
  const encryptionService = new JwtEncryptionService(config)

  return res.redirect(await getAuthRedirectUri(req, config, encryptionService, scope))
}

async function getAuthRedirectUri(req: Request, authConfig: CompanyAuthConfig,
                                  encryptionService: JwtEncryptionService,
                                  scope?: string): Promise<string> {

  const originalUrl: string = req.originalUrl
  const nonce: string = encryptionService.generateNonce()
  const encodedNonce: string = await encryptionService.jweEncodeWithNonce(originalUrl, nonce)

  return await createAuthUri(encodedNonce, authConfig, scope)
}

async function createAuthUri(encodedNonce: string,
                             authConfig: CompanyAuthConfig, scope?: string): Promise<string> {
  let authUri: string = `${authConfig.authUri}`.concat(
    '?',
    `client_id=${authConfig.accountClientId}`,
    `&redirect_uri=${authConfig.callbackUri}`,
    `&response_type=code`)

  if (scope) {
    authUri = authUri.concat(
      `&scope=${scope}`
    )
  }

  authUri = authUri.concat(
    `&state=${encodedNonce}`
  )

  return authUri
}

function createScope(companyNumber: string, config: CompanyAuthConfig): string | undefined {
  let scope

  if (config.useFineGrainScopesModel === '1') {
    // New fine grain scope model
    scope = SCOPE_USER_WRITE_FULL
    if (companyNumber) {
      scope += ' ' + SCOPE_COMPANY_WRITE_FULL_FORMAT.replace('{COMPANY_NUMBER}', companyNumber)
    }
  } else if (companyNumber != null) {
    // Legacy company scope
    scope = LEGACY_COMPANY_SCOPE_PREFIX + companyNumber
  }

  return scope
}

