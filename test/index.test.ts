import { Session, SessionStore } from '@companieshouse/node-session-handler'
import { SessionKey } from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import { ISignInInfo } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import { assert, expect } from 'chai'
import { Response } from 'express'
import sinon from 'sinon'
import { instance, mock, when } from 'ts-mockito'
import { authMiddleware, AuthOptions, CsrfProtectionMiddleware, CsrfOptions, CsrfTokensMismatchError, MissingCsrfSessionToken } from '../src'
import {
  generateRequest,
  generateResponse,
  generateSignInInfo, generateSignInInfoAuthedForCompany
} from './mockGeneration'
import { Cookie } from '@companieshouse/node-session-handler/lib/session/model/Cookie'

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

describe("CSRF Middleware enabled", () => {
  let redirectStub: sinon.SinonStub
  let opts: CsrfOptions
  let mockResponse: Response
  let mockNext: sinon.SinonStub
  let sessionStore: SessionStore
  let cookie: Cookie
  const newCsrfToken = "497a33e7-47be-4508-bf9d-0dd087fcf53b"

  beforeEach(() => {
    redirectStub = sinon.stub()
    sessionStore = mock(SessionStore)
    opts = {
      enabled: true,
      // @ts-ignore
      sessionStore: sinon.mock(sessionStore),
      csrfTokenFactory: () => newCsrfToken
    }
    mockResponse = generateResponse()
    mockResponse.redirect = redirectStub
    mockNext = sinon.stub()
    cookie = Cookie.createNew("c-is-for-cookie-which-is-good-enough-for-me");
  });

  afterEach(() => {
    sinon.restore()
  })

  it("calls next with no args when csrf token in request headers matches csrf token in session", () => {
    const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
    const sessionMock = mock(Session);
    const mockRequest = generateRequest(instance(sessionMock), csrfToken, undefined, "POST");

    when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

    CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

    assert(mockNext.calledOnceWithExactly())
  });

  it("calls next with no args when csrf token in request body matches csrf token in session", () => {
    const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
    const sessionMock = mock(Session);
    const mockRequest = generateRequest(instance(sessionMock), undefined, csrfToken, "POST");

    when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

    CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

    assert(mockNext.calledOnceWithExactly())
  });

  it("calls next with error when csrf token in header does not match", () => {
    const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
    const sessionMock = mock(Session);
    const mockRequest = generateRequest(instance(sessionMock), "58ff006d-8c3c-4590-aa3c-c7c594fb422e", undefined, "POST");

    when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

    CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

    assert(mockNext.calledWithMatch(sinon.match((error) => error instanceof CsrfTokensMismatchError && error.message === "Invalid CSRF token.")));
  });

  it("calls next with error when csrf token in body does not match", () => {
    const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
    const sessionMock = mock(Session);
    const mockRequest = generateRequest(instance(sessionMock), undefined, "58ff006d-8c3c-4590-aa3c-c7c594fb422e", "POST");

    when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

    CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

    assert(mockNext.calledWithMatch(sinon.match((error) => error instanceof CsrfTokensMismatchError && error.message === "Invalid CSRF token.")));
  });

  it("calls next with no args when not post", () => {
    const sessionMock = mock(Session);
    const mockRequest = generateRequest(instance(sessionMock));

    CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

    assert(mockNext.calledOnceWith());
  });

  it("prioritises body over header", () => {
    const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
    const sessionMock = mock(Session);
    const mockRequest = generateRequest(instance(sessionMock), "e1f1ba25-e129-490c-9675-47805b878dcd", csrfToken, "POST");

    when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

    CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

    assert(mockNext.calledOnceWithExactly())
  });

  it("Generates csrf token and stores in session when not found in session for non-mutable request", async () => {
    const sessionMock = mock(Session);
    const mockRequest = generateRequest(instance(sessionMock));
    mockRequest.cookies = {
      "_SID": cookie.value
    }

    when(sessionMock.data).thenReturn({
      [SessionKey.Expires]: 1223123454
    })

    when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(undefined);
    // @ts-ignore
    opts.sessionStore.expects("store").once().withArgs(
      sinon.match.defined,
      sinon.match({
        [SessionKey.Expires]: 1223123454,
        [SessionKey.CsrfToken]: newCsrfToken
      })
    );

    CsrfProtectionMiddleware({
      ...(opts),
      sessionStore: sessionStore
    })(mockRequest, mockResponse, mockNext)

    sinon.verify()

  })

  it("does not generate csrf token or store in session when not found in session for non-mutable request and not instructed to", async () => {
    const sessionMock = mock(Session);
    const mockRequest = generateRequest(instance(sessionMock));
    mockRequest.cookies = {
      "_SID": cookie.value
    }

    when(sessionMock.data).thenReturn({
      [SessionKey.Expires]: 1223123454
    })

    when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(undefined);
    // @ts-ignore
    opts.sessionStore.expects("store").never();

    CsrfProtectionMiddleware({
      ...(opts),
      createWhenCsrfTokenAbsent: false,
      sessionStore: sessionStore
    })(mockRequest, mockResponse, mockNext)

    sinon.verify()

  })

  it("sets the csrf token as part of locals", () => {
    const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
    const sessionMock = mock(Session);
    const mockRequest = generateRequest(instance(sessionMock), "e1f1ba25-e129-490c-9675-47805b878dcd", csrfToken, "POST");

    when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

    CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

    assert.equal(mockResponse.locals.csrfToken, csrfToken)
  })

  it("throws error when csrf token not found in session for mutable request", async () => {
    const sessionMock = mock(Session);
    const mockRequest = generateRequest(instance(sessionMock));
    mockRequest.method = "POST"
    mockRequest.cookies = {
      "_SID": cookie.value
    }

    when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(undefined);
    // @ts-ignore
    opts.sessionStore.expects("store").never()

    CsrfProtectionMiddleware({
      ...(opts),
      sessionStore: sessionStore
    })(mockRequest, mockResponse, mockNext)

    sinon.verify()

    assert(mockNext.calledWithMatch(sinon.match((error) => 
        error instanceof MissingCsrfSessionToken && error.message === "Session does not include CSRF token.")));

  })

  describe("custom header", () => {
    it("can locate csrf token in custom header", () => {
      const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
      const customHeaderName = "custom-csrf-token-header"

      const sessionMock = mock(Session);
      const mockRequest = generateRequest(instance(sessionMock), "blah", undefined);

      mockRequest.headers[customHeaderName] = csrfToken;
      mockRequest.method = "POST";

      when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

      CsrfProtectionMiddleware({
        enabled: true,
        headerName: customHeaderName,
        sessionStore: {} as SessionStore,
        csrfTokenFactory: () => newCsrfToken
      })(mockRequest, mockResponse, mockNext);

      assert(mockNext.calledOnceWithExactly())
    })
  })

  describe("custom field", () => {
    it("can locate csrf token in field in body", () => {
      const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
      const customParameterName = "custom-csrf-token-parameter"

      const sessionMock = mock(Session);
      const mockRequest = generateRequest(instance(sessionMock), undefined, "undefined");

      mockRequest.method = "POST";
      mockRequest.body = {
        [customParameterName]: csrfToken
      }

      when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

      CsrfProtectionMiddleware({
        enabled: true,
        parameterName: customParameterName,
        sessionStore: {} as SessionStore,
        csrfTokenFactory: () => newCsrfToken
      })(mockRequest, mockResponse, mockNext);

      assert(mockNext.calledOnceWithExactly())
    })
  })
});

describe("CSRF Middleware disabled", () => {
  let redirectStub: sinon.SinonStub
  let opts: CsrfOptions
  let mockResponse: Response
  let mockNext: sinon.SinonStub

  beforeEach(() => {
    redirectStub = sinon.stub()
    opts = {
      enabled: false,
      sessionStore: {} as SessionStore,
      csrfTokenFactory: () => "newCsrfToken"
    }
    mockResponse = generateResponse()
    mockResponse.redirect = redirectStub
    mockNext = sinon.stub()
  });

  it("Calls next", () => {
    const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
    const sessionMock = mock(Session);
    const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "POST");

    when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

    CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

    assert(mockNext.calledOnceWithExactly())
  })
})
