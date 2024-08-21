import { Session, SessionStore } from '@companieshouse/node-session-handler'
import { SessionKey } from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import { assert } from 'chai'
import { Response } from 'express'
import sinon from 'sinon'
import { instance, mock, when } from 'ts-mockito'
import { CsrfProtectionMiddleware, CsrfOptions, CsrfTokensMismatchError, MissingCsrfSessionToken, CsrfError, SessionUnsetError } from '../../src/csrf-protection'
import {
    generateRequest,
    generateResponse,
} from '../mockGeneration'
import { Cookie } from '@companieshouse/node-session-handler/lib/session/model/Cookie'
import  { extractFields } from '../../src/csrf-protection/middleware'


describe("csrf-protection/middleware", () => {
    describe("CSRF Middleware enabled", () => {
        let redirectStub: sinon.SinonStub
        let opts: CsrfOptions
        let mockResponse: Response
        let mockNext: sinon.SinonStub
        let mockExtractFields: sinon.SinonSpy
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
            mockExtractFields = sinon.spy(extractFields);
        });

        afterEach(() => {
            sinon.restore()
        })

        it("calls next with no args when csrf token in request headers matches csrf token in session", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), undefined, csrfToken, undefined, "POST");

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert(mockNext.calledOnceWithExactly())
        });

        it("calls next with no args when csrf token in request body matches csrf token in session", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, csrfToken, "POST");

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert(mockNext.calledOnceWithExactly())
        });

        it.skip("calls next with no args when csrf token in request body matches csrf token in session and content-type multipart/form-data", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const customHeaders = { 'content-type': 'multipart/form-data; boundary=----WebKitFormBoundaryAg3cRN2ZpW4BrFIu' }
            const mockRequest = generateRequest(instance(sessionMock), customHeaders, undefined, csrfToken, "POST");

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert(mockExtractFields.calledOnce);
            assert(mockNext.calledOnceWithExactly())
        });

        it("calls next with error when csrf token in header does not match", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), undefined, "58ff006d-8c3c-4590-aa3c-c7c594fb422e", undefined, "POST");

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert(mockNext.calledWithMatch(sinon.match((error) => error instanceof CsrfTokensMismatchError && error.message === "Invalid CSRF token.")));
        });

        it("calls next with error when csrf token in body does not match", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "58ff006d-8c3c-4590-aa3c-c7c594fb422e", "POST");

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
            const mockRequest = generateRequest(instance(sessionMock), undefined, "e1f1ba25-e129-490c-9675-47805b878dcd", csrfToken, "POST");

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

            assert(mockNext.calledOnceWith());
        })

        it("raises error when post and no session set", async () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(undefined, undefined, csrfToken, undefined, "POST");
            mockRequest.cookies = {
                "_SID": cookie.value
            }

            when(sessionMock.data).thenReturn({
                [SessionKey.Expires]: 1223123454
            })


            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(undefined);

            CsrfProtectionMiddleware({
                ...(opts),
                createWhenCsrfTokenAbsent: false,
                sessionStore: sessionStore
            })(mockRequest, mockResponse, mockNext)

            sinon.verify()

            const nextCall = mockNext.getCall(0)

            assert(nextCall.args[0] instanceof SessionUnsetError)
            assert(nextCall.args[0].message == "Session not set.")
        })

        it("calls next when get and no session set", async () => {
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(undefined);
            mockRequest.cookies = {
                "_SID": cookie.value
            }

            when(sessionMock.data).thenReturn({
                [SessionKey.Expires]: 1223123454
            })

            // @ts-ignore
            opts.sessionStore.expects("store").never();

            CsrfProtectionMiddleware({
                ...(opts),
                createWhenCsrfTokenAbsent: false,
                sessionStore: sessionStore
            })(mockRequest, mockResponse, mockNext)

            sinon.verify()

            assert(mockNext.calledOnceWith());
        })

        it("sets the csrf token as part of locals", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), undefined, "e1f1ba25-e129-490c-9675-47805b878dcd", csrfToken, "POST");

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

        it("can identify Csrf error", () => {
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

            assert(mockNext.calledWithMatch(sinon.match((error) => error instanceof CsrfError)))
        })

        describe("custom header", () => {
            it("can locate csrf token in custom header", () => {
                const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
                const customHeaderName = "custom-csrf-token-header"

                const sessionMock = mock(Session);
                const mockRequest = generateRequest(instance(sessionMock), undefined, "blah", undefined);

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
                const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "undefined");

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
            const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, undefined, "POST");

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert(mockNext.calledOnceWithExactly())
        })
    })
});
