import { expect } from 'chai'
import * as jose from 'node-jose'
import {CompanyAuthConfig} from '../../src'
import JwtEncryptionService from '../../src/encryption/jwt.encryption.service'

// This is just a random valid nonce
const NONCE = '123bh*'
const RETURN_URI = 'https://test.uri.gov.uk/testing'
// This Request key is just a random 256 bit base64 encoded string
const OAUTH2_REQUEST_KEY = 'uqq1imjrxynuNrPPSr32fsC5KQaHV42uu08MKgizyj0='

describe('Web Security tests', () => {

  it('Assert JWE encoding is performed correctly with URI content', async () => {

    const decodedKey = Buffer.from(OAUTH2_REQUEST_KEY, 'base64')

    const ks = await jose.JWK.asKeyStore([{
      alg: 'A128CBC-HS256',
      k: decodedKey,
      kid: 'key',
      kty: 'oct',
      use: 'enc',
    }])

    const companyAuthConfig: CompanyAuthConfig = {
      accountClientId: 'CLIENT',
      accountRequestKey: OAUTH2_REQUEST_KEY,
      authUri: 'AUTH_URI',
      callbackUri: 'CALLBACK_URI',
      companyNumber: '12345678',
      useFineGrainScopesModel: '0'
    }

    const jwtEncryptionService = new JwtEncryptionService(companyAuthConfig)

    const jwe = await jwtEncryptionService.jweEncodeWithNonce(RETURN_URI, NONCE)

    await jose.JWE.createDecrypt(ks).
    decrypt(jwe).
    then((result) => {
      const decodedPayload = JSON.parse(Buffer.from(result.plaintext).toString())
      const decodedNonce = decodedPayload.nonce
      const decodedContent = decodedPayload.content
      expect(decodedNonce).to.equal(NONCE)
      expect(decodedContent).to.equal(RETURN_URI)
    })
  })

  it('Assert a valid nonce is created', () => {
    const companyAuthConfig: CompanyAuthConfig = {
      accountClientId: 'CLIENT',
      accountRequestKey: OAUTH2_REQUEST_KEY,
      authUri: 'AUTH_URI',
      callbackUri: 'CALLBACK_URI',
      companyNumber: '12345678',
      useFineGrainScopesModel: '0'
    }

    const jwtEncryptionService = new JwtEncryptionService(companyAuthConfig)

    const nonce = jwtEncryptionService.generateNonce()
    expect(nonce.length).to.equal(8)
  })
})
