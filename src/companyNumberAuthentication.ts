import 'ch-node-session-handler'
import { Request, RequestHandler, Response } from 'express'

import { CompanyAuthConfig } from 'app/models/companyAuthConfig'
import JwtEncryptionService from 'app/services/jwtEncryptionService'

const OATH_SCOPE_PREFIX = 'https://api.companieshouse.gov.uk/company/'

export const authMiddleware = (config: CompanyAuthConfig): RequestHandler => async (
    req: Request,
    res: Response
) => {

    const encryptionService = new JwtEncryptionService(config)
    const companyNumber = config.companyNumber
    // const signInInfo: ISignInInfo = req.session!.get<ISignInInfo>(SessionKey.SignInInfo)!

    // if (isAuthorisedForCompany(signInInfo, companyNumber)) {
    //     logger.info(`User is authenticated for ${companyNumber}`)
    //     next()
    // }

    return res.redirect(await getAuthRedirectUri(req, config, encryptionService, companyNumber))
}

// function isAuthorisedForCompany(signInInfo: ISignInInfo, companyNumber: string): boolean {
//     return signInInfo[SignInInfoKeys.CompanyNumber] === companyNumber
// }


async function getAuthRedirectUri(req: Request, authConfig: CompanyAuthConfig,
                                  encryptionService: JwtEncryptionService,
                                  companyNumber?: string): Promise<string> {

    const originalUrl: string = req.originalUrl
    const scope: string = OATH_SCOPE_PREFIX + companyNumber
    const nonce: string = encryptionService.generateNonce()
    const encodedNonce: string = await encryptionService.jweEncodeWithNonce(originalUrl, nonce)

    // Session is read-only, how do I save Nonce into session?
    // req.session!.data[SessionKey.OAuth2Nonce] = nonce

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
