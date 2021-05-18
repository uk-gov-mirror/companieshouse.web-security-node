import { Session } from '@companieshouse/node-session-handler'
import { ISignInInfo } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import { Request, Response } from 'express'
import sinon from 'sinon'
import {SignInInfoKeys} from '@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys'
import {UserProfileKeys} from '@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys'

export function generateResponse(): Response {
  const res: Response = Object.create(require('express').response)
  res.redirect = sinon.stub().withArgs(sinon.match.any)
  res.locals = {}
  return res
}

export function generateSignInInfo(mockUserId: string, signedIn: number): ISignInInfo {
  return {
    signed_in: signedIn,
    user_profile: {
      id: mockUserId
    }
  }
}

export function generateSignInInfoAuthedForCompany(mockUserId: string,
                                                   signedIn: number, companyNumber: string,
                                                   legacyScope: boolean): ISignInInfo {
  const signInInfo: ISignInInfo = generateSignInInfo(mockUserId, signedIn)
  signInInfo[SignInInfoKeys.CompanyNumber] = companyNumber
  let scope
  if (legacyScope) {
    scope = `https://api.companies-house/company/${companyNumber}`
  } else {
    scope = `https://api.companies-house/company/${companyNumber}/admin.write-full`
  }

  signInInfo[SignInInfoKeys.UserProfile] =
    {[UserProfileKeys.Scope] : scope}
  return signInInfo
}

export function generateRequest(requestSession?: Session): Request {
  const request: Request = {
    headers: {
      host: 'localhost'
   }
  } as Request

  if (requestSession) {
    request.session = requestSession
  }

  return request
}
