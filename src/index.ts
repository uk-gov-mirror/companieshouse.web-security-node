import '@companieshouse/node-session-handler'
import { SessionKey } from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import { SignInInfoKeys } from '@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys'
import { ISignInInfo, IUserProfile } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import { createLogger } from '@companieshouse/structured-logging-node'
import { NextFunction, Request, RequestHandler, Response } from 'express'

import JwtEncryptionService from 'app/encryption/jwtEncryptionService';

const APP_NAME = 'web-security-node';
const logger = createLogger(APP_NAME);

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

const OATH_SCOPE_PREFIX = 'https://api.companieshouse.gov.uk/company/'

export interface CompanyAuthConfig {
  accountUrl: string,
  companyNumber: string
  accountRequestKey: string,
  accountClientId: string,
  chsUrl: string,
}

export const companyAuthMiddleware = (config: CompanyAuthConfig): RequestHandler => async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
  const encryptionService = new JwtEncryptionService(config)
  const companyNumber = config.companyNumber;

  return res.redirect(await getAuthRedirectUri(req, config, encryptionService, companyNumber))
  next()
}

async function getAuthRedirectUri(req: Request, authConfig: CompanyAuthConfig,
                                  encryptionService: JwtEncryptionService,
                                  companyNumber?: string): Promise<string> {

  const originalUrl: string = req.originalUrl
  const scope: string = OATH_SCOPE_PREFIX + companyNumber
  const nonce: string = encryptionService.generateNonce()
  const encodedNonce: string = await encryptionService.jweEncodeWithNonce(originalUrl, nonce)

  return await createAuthUri(encodedNonce, authConfig, scope)
}

async function createAuthUri(encodedNonce: string,
                             authConfig: CompanyAuthConfig, scope: string): Promise<string> {
  return `${authConfig.accountUrl}/oauth2/authorise`.concat(
      '?',
      `client_id=${authConfig.accountClientId}`,
      `&redirect_uri=${authConfig.chsUrl}/oauth2/user/callback`,
      `&response_type=code`,
      `&scope=${scope}`,
      `&state=${encodedNonce}`)
}

