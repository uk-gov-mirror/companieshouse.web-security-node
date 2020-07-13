import 'ch-node-session-handler'
import { NextFunction, Request, RequestHandler, Response } from 'express'

import JwtEncryptionService from 'app/encryption/jwtEncryptionService'

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
