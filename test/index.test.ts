import { Session} from '@companieshouse/node-session-handler'
import { SessionKey } from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import { ISignInInfo } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import { assert, expect } from 'chai'
import { Response } from 'express'
import sinon from 'sinon'
import { instance, mock, when } from 'ts-mockito'
import { authMiddleware, AuthOptions } from '../src'
import {
  generateRequest,
  generateResponse,
  generateSignInInfo, generateSignInInfoAuthedForCompany
} from './mockGeneration'

describe('Authentication Middleware', () => {
  const mockReturnUrl = 'accounts/signin?return_to=origin'
  const mockUserId = 'sA=='

  let redirectStub: sinon.SinonStub
  let opts: AuthOptions
  let mockResponse: Response
  let mockNext: sinon.SinonStub

  beforeEach(() => {
    redirectStub = sinon.stub()
    opts = {
      returnUrl: 'origin',
      chsWebUrl: 'accounts',
    }
    mockResponse = generateResponse()
    mockResponse.redirect = redirectStub
    mockNext = sinon.stub()
  })

  it('When CHS Web Url is blank, throw error', () => {
    const mockRequest = generateRequest()
    opts.chsWebUrl = ''

    expect(() => authMiddleware(opts)(mockRequest, mockResponse, mockNext)).to.throw('Required Field CHS Web URL not set')
    assert(redirectStub.notCalled)
    assert(mockNext.notCalled)
  })

  it('When there is no session the middleware should not call next and should trigger redirect', () => {
    const mockRequest = generateRequest()

    authMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(redirectStub.calledOnceWith(mockReturnUrl))
    assert(mockNext.notCalled)
  })

  it('When the user is not logged in the middleware should not call next and should trigger redirect', () => {
    const unAuthedSession = mock(Session)
    const mockRequest = generateRequest(instance(unAuthedSession))

    when(unAuthedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 0))
    authMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(redirectStub.calledOnceWith(mockReturnUrl))
    assert(mockNext.notCalled)
  })

  it('When the user is logged in the middleware should call next', () => {
    const authedSession = mock(Session)
    const mockRequest = generateRequest(instance(authedSession))

    when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1))
    authMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(mockNext.calledOnce)
  })
})

describe('Authentication Middleware with company number', () => {
  const mockReturnUrl = 'accounts/signin?return_to=origin&company_number=12345678'
  const mockUserId = 'sA=='

  let redirectStub: sinon.SinonStub
  let opts: AuthOptions
  let mockResponse: Response
  let mockNext: sinon.SinonStub

  beforeEach(() => {
    redirectStub = sinon.stub()
    opts = {
      returnUrl: 'origin',
      chsWebUrl: 'accounts',
      companyNumber: '12345678'
    }
    mockResponse = generateResponse()
    mockResponse.redirect = redirectStub
    mockNext = sinon.stub()
  })

  it('When the user is not authed for company the middleware should not call next and should trigger redirect', () => {
    const authedSession = mock(Session)
    const mockRequest = generateRequest(instance(authedSession))

    when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1))
    authMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(redirectStub.calledOnceWith(mockReturnUrl))
    assert(mockNext.notCalled)
  })

  it('When the user is authenticated for company the middleware should call next', () => {
    const authedSession = mock(Session)
    const mockRequest = generateRequest(instance(authedSession))

    when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo))
      .thenReturn(generateSignInInfoAuthedForCompany(mockUserId, 1, '12345678'))
    authMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(mockNext.calledOnce)
    assert(redirectStub.notCalled)
  })
})

describe('Test tokenPermissions conditionals in authMiddleware', () => {
  // todo
}

describe('Test tokenPermissionsPresent function', () => {
  let opts: AuthOptions
  let userProfile:

  beforeEach(() => {
    opts = {
      returnUrl: 'origin',
      chsWebUrl: 'accounts',
      companyNumber: '12345678'
      // todo -- add requestScopeAndPermissions
    }

    userProfile = {
      // todo
    }
  })

  // should we add a test for the case for requestScopeAndPermissions.tokenPermissions is undefined/null/not present?

  it('When the userProfile tokenPermissions is not present, return false', () => {
      // should this not return true? -- see my comment in additionalScopeIsRequired function
  })

  it('When the requestScopeAndPermissions tokenPermissions contains a key not present in userProfile tokenPermissions, return true', () => {
  })

  it('When the requestScopeAndPermissions tokenPermissions contains a key in userProfile tokenPermissions, but the userProfile token permission lacks a request value, return true', () => {
  })

  it('When the requestScopeAndPermissions tokenPermissions contains a key in userProfile tokenPermissions, and the corresponding userProfile token permission request value matches, return false', () => {
  })

  it('When the requestScopeAndPermissions tokenPermissions contains a key in userProfile tokenPermissions, and the corresponding userProfile token permission request value matches and contains additional scopes, return false', () => {
  })
})

/* // for reference whilst writing tests:

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

*/
