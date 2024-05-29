import { Session } from '@companieshouse/node-session-handler'
import { assert } from 'chai'
import { Response } from 'express'
import sinon from 'sinon'
import { instance, mock } from 'ts-mockito'
import { CsrfTokensMismatchError, MissingCsrfSessionToken, CsrfError, SessionUnsetError, CsrfFailureErrorHandler } from '../../src/csrf-protection'
import {
  generateRequest,
  generateResponse,
} from '../mockGeneration'

describe("CSRF Error handler", () => {

    let redirectStub: sinon.SinonStub
    let statusStub: sinon.SinonStub
    let sendStub: sinon.SinonStub
    let mockResponse: Response
    let mockNext: sinon.SinonStub
  
    const defaultStatusCode = 403;
    const defaultErrorMessage = "CSRF Token Could not be matched";
  
  
    beforeEach(() => {
      redirectStub = sinon.stub()
      statusStub = sinon.stub()
      sendStub = sinon.stub()
      mockResponse = generateResponse()
      mockResponse.redirect = redirectStub
      mockResponse.status = statusStub
      mockResponse.send = sendStub
      mockNext = sinon.stub()
  
      statusStub.returns(mockResponse);
      sendStub.returns(mockResponse);
    });
  
    describe("default behaviour", () => {
      const errorHandler = CsrfFailureErrorHandler();
      const expectedStatusCode = defaultStatusCode;
      const expectedErrorMessage = defaultErrorMessage;
  
  
      [
        new SessionUnsetError("Session Unset"),
        new MissingCsrfSessionToken("Token missing"),
        new CsrfTokensMismatchError("Mismatch")
      ].forEach(error => {
  
        it(`Handles ${error}`, () => {
          const sessionMock = mock(Session);
          const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "POST");
  
          errorHandler(error, mockRequest, mockResponse, mockNext);
  
          assert(statusStub.calledOnceWithExactly(expectedStatusCode));
          assert(sendStub.calledOnceWithExactly(expectedErrorMessage))
          assert(mockNext.notCalled)
        })
      })
  
      it("does not handle a non-CSRF error", () => {
  
        const sessionMock = mock(Session);
        const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "POST");
  
        const error = new Error("Not CSRF Error")
  
        errorHandler(error, mockRequest, mockResponse, mockNext);
  
        assert(statusStub.notCalled);
        assert(sendStub.notCalled)
        assert(mockNext.calledOnceWithExactly(error))
      })
    });
  
    it("can override status and message", () => {
      const expectedStatusCode = 401;
      const expectedErrorMessage = "CSRF Token Error";
      const errorHandler = CsrfFailureErrorHandler({
        defaultStatusCode: expectedStatusCode,
        defaultFailureReason: expectedErrorMessage
      });
      const error = new CsrfTokensMismatchError("Mismatch");
  
      const sessionMock = mock(Session);
      const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "POST");
  
      errorHandler(error, mockRequest, mockResponse, mockNext);
  
      assert(statusStub.calledOnceWithExactly(expectedStatusCode));
      assert(sendStub.calledOnceWithExactly(expectedErrorMessage))
      assert(mockNext.notCalled)
    })
  
    describe("granular error handling", () => {
      const sessionCode = 500;
      const missingCode = 401;
      const mismatchCode = 403;
  
      [
        [new SessionUnsetError("Session Unset"), sessionCode],
        [new MissingCsrfSessionToken("Token missing"), missingCode],
        [new CsrfTokensMismatchError("Mismatch"), mismatchCode]
      ].forEach((data) => {
        // @ts-expect-error This is known to be ok by typescript will be overzealous
        const [error, expectedStatusCode]: [CsrfError, number] = data;
  
        const responseMappings = {
          "SessionUnsetError": {
            statusCode: sessionCode,
            failureReason: "Session Unset"
          },
          "MissingCsrfSessionToken": {
            statusCode: missingCode,
            failureReason: "Token missing"
          },
          "CsrfTokensMismatchError": {
            statusCode: mismatchCode,
            failureReason: "Mismatch"
          }
        };
        const errorHandler = CsrfFailureErrorHandler({
          responseMappings
        })
  
        it(`handles ${error} respnse has status of ${expectedStatusCode}`, () => {
  
          const sessionMock = mock(Session);
          const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "POST");
  
          errorHandler(error, mockRequest, mockResponse, mockNext);
  
          assert(statusStub.calledOnceWithExactly(expectedStatusCode));
          assert(sendStub.calledOnceWithExactly(error.message))
          assert(mockNext.notCalled)
        })
      });
  
      it("falls back on default details when no mapping", () => {
        const responseMappings = {
          "SessionUnsetError": {
            statusCode: sessionCode,
            failureReason: "Session Unset"
          },
        }
  
        const errorHandler = CsrfFailureErrorHandler({
          responseMappings
        })
  
        const sessionMock = mock(Session);
        const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "POST");
  
        const error = new CsrfTokensMismatchError("Mismatch");
  
  
        const expectedStatusCode = defaultStatusCode;
        const expectedErrorMessage = defaultErrorMessage
  
        errorHandler(error, mockRequest, mockResponse, mockNext);
  
        assert(statusStub.calledOnceWithExactly(expectedStatusCode));
        assert(sendStub.calledOnceWithExactly(expectedErrorMessage))
        assert(mockNext.notCalled)
      });
  
      it("falls back on default message when not supplied", () => {
        const responseMappings = {
          "SessionUnsetError": {
            statusCode: sessionCode,
          },
        }
  
        const errorHandler = CsrfFailureErrorHandler({
          responseMappings
        })
  
        const sessionMock = mock(Session);
        const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "POST");
  
        const error = new SessionUnsetError("Mismatch");
  
        const expectedErrorMessage = defaultErrorMessage;
  
        errorHandler(error, mockRequest, mockResponse, mockNext);
  
        assert(statusStub.calledOnceWithExactly(sessionCode));
        assert(sendStub.calledOnceWithExactly(expectedErrorMessage))
        assert(mockNext.notCalled)
      })
  
      it("falls back on default status when not supplied", () => {
        const responseMappings = {
          "SessionUnsetError": {
            failureReason: "Mismatch"
          },
        }
  
        const errorHandler = CsrfFailureErrorHandler({
          responseMappings
        })
  
        const sessionMock = mock(Session);
        const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "POST");
  
        const error = new SessionUnsetError("Mismatch");
  
        const expectedStatusCode = defaultStatusCode;
        const expectedErrorMessage = "Mismatch";
  
        errorHandler(error, mockRequest, mockResponse, mockNext);
  
        assert(statusStub.calledOnceWithExactly(expectedStatusCode));
        assert(sendStub.calledOnceWithExactly(expectedErrorMessage))
        assert(mockNext.notCalled)
      })
    })
  })
  