import { Response } from 'express'
import sinon from 'sinon'
import { assert, expect } from 'chai'
import { instance, mock, when } from 'ts-mockito'
import { Session} from '@companieshouse/node-session-handler'
import { SessionKey } from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import { ISignInInfo } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import { authMiddleware, AuthOptions } from '../src'
import {
  generateRequest,
  generateResponse,
  generateSignInInfo,
  generateSignInInfoAuthedForCompany,
  generateSignInInfoWithUpgradedCompanyAuth
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
    //@ts-ignore
    const mockRequest = generateRequest({ ...instance(unAuthedSession), data: {} })

    when(unAuthedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 0))
    authMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(redirectStub.calledOnceWith(mockReturnUrl))
    assert(mockNext.notCalled)
  })

  it('When the user is logged in the middleware should call next', () => {
    const authedSession = mock(Session)
    //@ts-ignore
    const mockRequest = generateRequest({ ...instance(authedSession), data: {} })

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

  it('When the user is not authenticated for company the middleware should not call next and should trigger redirect', () => {
    const authedSession = mock(Session)
    // @ts-ignore
    const mockRequest = generateRequest({ ...instance(authedSession), data: {} })

    when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1))
    authMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(redirectStub.calledOnceWith(mockReturnUrl))
    assert(mockNext.notCalled)
  })

  it('When the user is authenticated for company the middleware should call next', () => {
    const authedSession = mock(Session)
    // @ts-ignore
    const mockRequest = generateRequest({ ...instance(authedSession), data: {} })

    when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo))
      .thenReturn(generateSignInInfoAuthedForCompany(mockUserId, 1, '12345678'))
    authMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(mockNext.calledOnce)
    assert(redirectStub.notCalled)
  })

   it("Should redirect with company_force_auth=true when forceAuthCode is true and companyNumber is missing in session", () => {
        const expectedAuthReturnUrl = 'accounts/signin?return_to=origin&company_number=12345678&company_force_auth=true'
        const forceAuthCodeOptions = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            companyNumber: "12345678",
            forceAuthCode: true
        }
        const authedSession = mock(Session)
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} })

        // Simulate user logged in but no company auth info
        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo))
            .thenReturn(generateSignInInfo(mockUserId, 1))

        authMiddleware(forceAuthCodeOptions)(mockRequest, mockResponse, mockNext)

        assert(redirectStub.calledOnceWith(expectedAuthReturnUrl), "Should redirect to expected URL")
        assert(mockNext.notCalled, "Next should not be called")
    })

    it("Should call next when forceAuthCode is false and user is authorised for company", () => {
        const forceAuthCodeOptions = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            companyNumber: "12345678",
            forceAuthCode: false
        }
        const authedSession = mock(Session)
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} })

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo))
            .thenReturn(generateSignInInfoAuthedForCompany(mockUserId, 1, "12345678"))

        authMiddleware(forceAuthCodeOptions)(mockRequest, mockResponse, mockNext)

        assert(mockNext.calledOnce, "Next should be called when forceAuthCode is false and user is authorised")
        assert(redirectStub.notCalled, "Redirect should not be called")
    })

    it("Should throw error if forceAuthCode is true but company number is missing", () => {
        const forceAuthCodeOptions = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            forceAuthCode: true
        }
        const authedSession = mock(Session)
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} })

        expect(() => authMiddleware(forceAuthCodeOptions)(mockRequest, mockResponse, mockNext)).to.throw('Required Field missing: forceAuthCode is true but company number not set')
        assert(redirectStub.notCalled)
        assert(mockNext.notCalled)
    })

it("Should redirect with company_force_auth=true when the user is not authorised for company", () => {
    // Arrange
    const expectedAuthReturnUrl = 'accounts/signin?return_to=origin&company_number=12345678&company_force_auth=true'
    const forceAuthCodeOptions = {
        returnUrl: "origin",
        chsWebUrl: "accounts",
        companyNumber: "12345678",
        forceAuthCode: true
    }
    const differentCompanyNumber = "12345"
    const authedSession = mock(Session)
    // @ts-ignore
    const mockRequest = generateRequest({ ...instance(authedSession), data: {} })

    // Simulate user authenticated for a different company
    when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo))
        .thenReturn(generateSignInInfoAuthedForCompany(mockUserId, 1, differentCompanyNumber))

    authMiddleware(forceAuthCodeOptions)(mockRequest, mockResponse, mockNext)

    assert(redirectStub.calledOnceWith(expectedAuthReturnUrl), "Should redirect to expected URL")
    assert(mockNext.notCalled, "Next should not be called")
})

it("Should redirect with company_force_auth=true when the user is authorised for company but doesn't have upgraded company auth", () => {
    // Arrange
    const expectedAuthReturnUrl = 'accounts/signin?return_to=origin&company_number=12345678&company_force_auth=true'
    const forceAuthCodeOptions = {
        returnUrl: "origin",
        chsWebUrl: "accounts",
        companyNumber: "12345678",
        forceAuthCode: true
    }
    const authedSession = mock(Session)
    // @ts-ignore
    const mockRequest = generateRequest({ ...instance(authedSession), data: {} })

    // Simulate user authenticated for company but missing upgraded company auth
    when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo))
        .thenReturn(generateSignInInfoAuthedForCompany(mockUserId, 1, "12345678"))

    authMiddleware(forceAuthCodeOptions)(mockRequest, mockResponse, mockNext)

    assert(redirectStub.calledOnceWith(expectedAuthReturnUrl), "Should redirect to expected URL")
    assert(mockNext.notCalled, "Next should not be called")
  
})

it("Should redirect with company_force_auth=true when the user is authorised for company but has expired upgraded company auth", () => {
    
    const expectedAuthReturnUrl = 'accounts/signin?return_to=origin&company_number=12345678&company_force_auth=true'
    const forceAuthCodeOptions = {
        returnUrl: "origin",
        chsWebUrl: "accounts",
        companyNumber: "12345678",
        forceAuthCode: true
    }
    const authedSession = mock(Session)
    // @ts-ignore
    const mockRequest = generateRequest({ ...instance(authedSession), data: {} })
    const expiredTimeStamp = Math.floor(Date.now() / 1000 - 1).toString()

    when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo))
        .thenReturn(generateSignInInfoWithUpgradedCompanyAuth(mockUserId, 1, "12345678", expiredTimeStamp))
    authMiddleware(forceAuthCodeOptions)(mockRequest, mockResponse, mockNext)

    assert(redirectStub.calledOnceWith(expectedAuthReturnUrl), "Should redirect to expected URL")
    assert(mockNext.notCalled, "Next should not be called")
    expect(redirectStub.firstCall.args[0]).to.include("company_force_auth=true")
    expect(redirectStub.firstCall.args[0]).to.include("company_number=12345678")
})

it("Should redirect with company_force_auth=true when upgraded company auth timestamp is not a valid number", () => {
    const expectedAuthReturnUrl = 'accounts/signin?return_to=origin&company_number=12345678&company_force_auth=true'
    const forceAuthCodeOptions = {
        returnUrl: "origin",
        chsWebUrl: "accounts",
        companyNumber: "12345678",
        forceAuthCode: true
    }
    const authedSession = mock(Session)
    // @ts-ignore
    const mockRequest = generateRequest({ ...instance(authedSession), data: {} })
    const invalidTimeStamp = "not-a-number"

    when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo))
        .thenReturn(generateSignInInfoWithUpgradedCompanyAuth(mockUserId, 1, "12345678", invalidTimeStamp))

    authMiddleware(forceAuthCodeOptions)(mockRequest, mockResponse, mockNext)

    assert(redirectStub.calledOnceWith(expectedAuthReturnUrl), "Should redirect to expected URL")
    assert(mockNext.notCalled, "Next should not be called")
    expect(redirectStub.firstCall.args[0]).to.include("company_force_auth=true")
    expect(redirectStub.firstCall.args[0]).to.include("company_number=12345678")
})

it("Should not redirect with company_force_auth=true and should call next when the user does have upgraded company auth", () => {
    // Arrange
    const authedSession = mock(Session)
    const forceAuthCodeOptions = {
        returnUrl: "origin",
        chsWebUrl: "accounts",
        companyNumber: "12345678",
        forceAuthCode: true
    }
    // @ts-ignore
    const mockRequest = generateRequest({ ...instance(authedSession), data: {} })
    const validTimeStamp = Math.floor((Date.now() / 1000) + 240).toString()

    // Simulate user with upgraded company auth
    when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo))
        .thenReturn(generateSignInInfoWithUpgradedCompanyAuth(mockUserId, 1, forceAuthCodeOptions.companyNumber, validTimeStamp))

    authMiddleware(forceAuthCodeOptions)(mockRequest, mockResponse, mockNext)

    assert(mockNext.calledOnce, "Next should be called when upgraded company auth is present and valid")
    assert(redirectStub.notCalled, "Redirect should not be called when upgraded company auth is present and valid")
})

})
