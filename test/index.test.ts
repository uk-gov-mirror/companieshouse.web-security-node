import { Session } from '@companieshouse/node-session-handler'
import { SessionKey } from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import { ISignInInfo } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import { assert } from 'chai'
import { Response } from 'express'
import sinon from 'sinon'
import { instance, mock, when } from 'ts-mockito'
import {authMiddleware, companyAuthMiddleware, AuthOptions, CompanyAuthConfig} from '../src'
import JwtEncryptionService from '../src/encryption/jwt.encryption.service'
import {
  generateRequest,
  generateResponse,
  generateSignInInfo,
  generateSignInInfoForAuthenticatedCompany
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
      accountWebUrl: 'accounts',
    }
    mockResponse = generateResponse()
    mockResponse.redirect = redirectStub
    mockNext = sinon.stub()
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

describe('Company Authentication Middleware', () => {

  let redirectStub: sinon.SinonStub
  let opts: CompanyAuthConfig
  let mockResponse: Response
  let mockNext: sinon.SinonStub
  let mockNonce: sinon.SinonStub
  let mockJWT: sinon.SinonStub

  beforeEach(() => {
    redirectStub = sinon.stub()
    opts = {
      authUri: "AUTH",
      companyNumber: "12345678",
      accountRequestKey: "KEY",
      accountClientId: "CLIENT_ID",
      callbackUri: "CALLBACK",
      useFineGrainScopesModel: "0"
    }
    mockResponse = generateResponse()
    mockResponse.redirect = redirectStub
    mockNext = sinon.stub()
    mockNonce = sinon.stub(JwtEncryptionService.prototype, 'generateNonce').returns('3')
    mockJWT = sinon.stub(JwtEncryptionService.prototype, 'jweEncodeWithNonce').returns(Promise.resolve('jwe'))
  })

  afterEach(() => {
    sinon.restore()
  })

  it('When the user is authed for company it should call next', () => {
    const authedSession = mock(Session)
    const mockRequest = generateRequest(instance(authedSession))
    const mockUserId = 'sA=='

    when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).
      thenReturn(generateSignInInfoForAuthenticatedCompany(mockUserId, "12345678"))
    companyAuthMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(mockNext.calledOnce)
    assert(mockNonce.notCalled)
    assert(mockJWT.notCalled)
  })

  it('When the user is authed for wrong company it should not call next', () => {
    const authedSession = mock(Session)
    const mockRequest = generateRequest(instance(authedSession))
    const mockUserId = 'sA=='

    when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).
    thenReturn(generateSignInInfoForAuthenticatedCompany(mockUserId, "87654321"))
    companyAuthMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(mockNext.notCalled)
    assert(mockNonce.calledOnce)
    assert(mockJWT.calledOnce)
  })

  it('When the user is not authed for any company it should not call next', () => {
    const mockUserId = 'sA=='
    const unAuthedSession = mock(Session)
    const mockRequest = generateRequest(instance(unAuthedSession))

    when(unAuthedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 0))
    companyAuthMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(mockNext.notCalled)
    assert(mockNonce.calledOnce)
    assert(mockJWT.calledOnce)
  })
})
