import { Session} from '@companieshouse/node-session-handler'
import { SessionKey } from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import { ISignInInfo, IUserProfile } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import {UserProfileKeys} from '@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys'
import { assert, expect } from 'chai'
import { Response } from 'express'
import sinon from 'sinon'
import { instance, mock, when } from 'ts-mockito'
import { authMiddleware, AuthOptions, additionalScopeIsRequired, acspProfileCreateAuthMiddleware } from '../src'
import {
  generateRequest,
  generateResponse,
  generateSignInInfo, generateSignInInfoAuthedForCompany,
  generateSignInInfoAuthedForScope
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

  it('When the user is not authenticated for company the middleware should not call next and should trigger redirect', () => {
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

  const mockReturnUrlWithScope = 'accounts/signin?return_to=origin&additional_scope=test_scope'
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
      requestScopeAndPermissions: {
        scope: "test_scope",
        tokenPermissions: {
          "test_permission": "create,update"
        }
      }
    }
    mockResponse = generateResponse()
    mockResponse.redirect = redirectStub
    mockNext = sinon.stub()
  })
  
  it('When there is no session and requestScopeAndPermissions, the middleware should not call next and should trigger redirect with additional scope', () => {

    const mockRequest = generateRequest()

    authMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(redirectStub.calledOnceWith(mockReturnUrlWithScope))
    assert(mockNext.notCalled)
  })

    
  it('When the user is not logged in the middleware and requestScopeAndPermissions should not call next and should trigger redirect with additional scope', () => {
    const unAuthedSession = mock(Session)
    const mockRequest = generateRequest(instance(unAuthedSession))
    const result = generateSignInInfoAuthedForScope(mockUserId, 0, "test_scope");
    

    when(unAuthedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(result)
    authMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(redirectStub.calledOnceWith(mockReturnUrlWithScope))
    assert(mockNext.notCalled)

  })

})

describe('Test tokenPermissions conditionals in acspProfileCreateAuthMiddleware wrapper', () => {

  const mockReturnUrlWithScope = 'accounts/signin?return_to=origin&additional_scope=https://identity.company-information.service.gov.uk/acsp-profile.create'

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
  
  it('When there is no session and acspProfileCreate, the middleware should not call next and should trigger redirect with additional scope', () => {

    const mockRequest = generateRequest()

    acspProfileCreateAuthMiddleware(opts)(mockRequest, mockResponse, mockNext)
    assert(redirectStub.calledOnceWith(mockReturnUrlWithScope))
    assert(mockNext.notCalled)
  })


})

describe('Test tokenPermissionsPresent function', () => {
  let options: AuthOptions
  let userProfile: IUserProfile

  beforeEach(() => {

    options = {
      returnUrl: 'origin',
      chsWebUrl: 'accounts',
      companyNumber: '12345678',
      requestScopeAndPermissions: {
        scope: "test_scope",
        tokenPermissions: {
          "test_permission": "create,update"
        }
      }
    }

    userProfile = {
      [UserProfileKeys.TokenPermissions]: {
        "overseas_entities": "create,update,delete",
        "user_orders": "create,read,update,delete",
        "acsp_profile": "create"
      }

    }
  })

    it('When the requestScopeAndPermissions is undefined, return false', () => {

      assert(!additionalScopeIsRequired(undefined, {}))
      assert(!additionalScopeIsRequired(null, {}))
    })

    it('When the userProfile tokenPermissions is not present, return true', () => {
      assert(additionalScopeIsRequired(options.requestScopeAndPermissions, {}))
    })

    it('When the requestScopeAndPermissions tokenPermissions contains a key not present in userProfile tokenPermissions, return true', () => {
      assert(additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile))
    })

    it('When the requestScopeAndPermissions tokenPermissions contains a key in userProfile tokenPermissions, but the userProfile token permission lacks a request value, return true', () => {
      userProfile = {
        [UserProfileKeys.TokenPermissions]: {
          "overseas_entities": "create,update,delete",
          "user_orders": "create,read,update,delete",
          "acsp_profile": "create",
          "test_permission": "create"  // missing update
        }
      }
      assert(additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile))
    })

    it('When the requestScopeAndPermissions tokenPermissions contains a key in userProfile tokenPermissions and the corresponding userProfile token permission request value matches, return false', () => {
      userProfile = {
        [UserProfileKeys.TokenPermissions]: {
          "overseas_entities": "create,update,delete",
          "user_orders": "create,read,update,delete",
          "acsp_profile": "create",
          "test_permission": "create,update"  
        }
      }
      assert( ! additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile))
 
    })

    it('When the requestScopeAndPermissions tokenPermissions contains a key in userProfile tokenPermissions and the corresponding userProfile token permission request value matches (but in wrong order and has spaces), return false', () => {
      userProfile = {
        [UserProfileKeys.TokenPermissions]: {
          "overseas_entities": "create,update,delete",
          "user_orders": "create,read,update,delete",
          "acsp_profile": "create",
          "test_permission": "update , create"  
        }
      }
      assert( ! additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile))
 
    })


    it('When the requestScopeAndPermissions tokenPermissions contains a key in userProfile tokenPermissions and the corresponding userProfile token permission request value matches (request permissions in different order), return false', () => {
      userProfile = {
        [UserProfileKeys.TokenPermissions]: {
          "overseas_entities": "create,update,delete",
          "user_orders": "create,read,update,delete",
          "acsp_profile": "create",
          "test_permission": "create,update"  
        }
      }
      if (options.requestScopeAndPermissions) {
         options.requestScopeAndPermissions.tokenPermissions = { "test_permission": "update,create" }

         assert( ! additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile))
      } else {
        expect.fail("has test data been changed ?");
      }
 
    })

  })

