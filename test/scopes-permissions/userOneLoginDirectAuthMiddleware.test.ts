import { assert } from "chai";
import { Response } from "express";
import sinon from "sinon";
import { Session } from "@companieshouse/node-session-handler";
import { SessionKey } from "@companieshouse/node-session-handler/lib/session/keys/SessionKey";
import { UserProfileKeys } from "@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys";
import { ISignInInfo } from "@companieshouse/node-session-handler/lib/session/model/SessionInterfaces";
import { instance, mock, when } from "ts-mockito";
import { AuthOptions } from "../../src";
import { userOneLoginDirectAuthMiddleware } from "../../src";
import {
    generateRequest,
    generateResponse
} from "../mockGeneration";

describe("Test tokenPermissions conditionals in userOneLoginDirectAuthMiddleware wrapper", () => {

    const expectedRedirectUrl = "accounts/signin?return_to=origin&additional_scope=https://account.companieshouse.gov.uk/user.write-full https://identity.company-information.service.gov.uk/user/one-login.force.direct";

    let redirectStub: sinon.SinonStub;
    let opts: AuthOptions;
    let mockResponse: Response;
    let mockNext: sinon.SinonStub;

    beforeEach(() => {
        redirectStub = sinon.stub();
        opts = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
        };
        mockResponse = generateResponse();
        mockResponse.redirect = redirectStub;
        mockNext = sinon.stub();
    });

    it("When there is no session, the middleware should not call next and should trigger redirect with correct scopes", () => {

        const mockRequest = generateRequest();

        userOneLoginDirectAuthMiddleware(opts)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(expectedRedirectUrl));
        assert(mockNext.notCalled);
    });

    it("When the user is signed in but lacks one_login: read permission, it should redirect", () => {
        const sessionMock = mock(Session);
        const mockRequest = generateRequest({ ...instance(sessionMock), data: {} } as Session);
        const signInInfo: ISignInInfo = {
            signed_in: 1,
            user_profile: {
                id: "mockUserId",
                [UserProfileKeys.TokenPermissions]: {
                    "other": "read"
                }
            }
        };
        when(sessionMock.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(signInInfo);

        userOneLoginDirectAuthMiddleware(opts)(mockRequest, mockResponse, mockNext);

        assert(redirectStub.calledOnceWith(expectedRedirectUrl));
        assert(mockNext.notCalled);
    });

    it("When the user is signed in and has one_login: read permission, it should call next()", () => {
        const sessionMock = mock(Session);
        const mockRequest = generateRequest({ ...instance(sessionMock), data: {} } as Session);
        const signInInfo: ISignInInfo = {
            signed_in: 1,
            user_profile: {
                id: "mockUserId",
                [UserProfileKeys.TokenPermissions]: {
                    "one_login": "read"
                }
            }
        };
        when(sessionMock.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(signInInfo);

        userOneLoginDirectAuthMiddleware(opts)(mockRequest, mockResponse, mockNext);

        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

});
