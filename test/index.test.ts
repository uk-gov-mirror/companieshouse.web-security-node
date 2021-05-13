import { Session } from '@companieshouse/node-session-handler'
import { SessionKey } from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import { ISignInInfo } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import { assert } from 'chai'
import { Response } from 'express'
import sinon from 'sinon'
import { instance, mock, when } from 'ts-mockito'
import { authMiddleware, AuthOptions } from '../src/index'
import { generateRequest, generateResponse, generateSignInInfo } from './mockGeneration'

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
