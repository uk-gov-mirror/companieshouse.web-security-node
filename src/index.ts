import '@companieshouse/node-session-handler'
import { SessionKey } from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import { SignInInfoKeys } from '@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys'
import { ISignInInfo, IUserProfile } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import { createLogger } from '@companieshouse/structured-logging-node'
import { NextFunction, Request, RequestHandler, Response } from 'express'

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

  logger.debug(`${JSON.stringify(options)} - Log options variables!`)
  
  if (!req.session) {
    logger.debug(`${appName} - handler: Session object is missing!`)
    return res.redirect(redirectURI)
  }

  const signInInfo: ISignInInfo = req.session.get<ISignInInfo>(SessionKey.SignInInfo) || {}
  const signedIn: boolean = signInInfo![SignInInfoKeys.SignedIn] === 1
  const userProfile: IUserProfile = signInInfo![SignInInfoKeys.UserProfile] || {}
  const userId: string | undefined = userProfile?.id

  logger.debug(`${JSON.stringify(signInInfo)} - Log signInInfo variables!`)

  if (!signedIn) {
    logger.info(`${appName} - handler: userId=${userId}, Not signed in... Redirecting to: ${redirectURI}`)
    return res.redirect(redirectURI)
  }

  logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`)
  next()
}
