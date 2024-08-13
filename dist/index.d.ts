import '@companieshouse/node-session-handler';
import { IUserProfile } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces';
import { UserProfileKeys } from '@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys';
import { RequestHandler } from 'express';
export * from './csrf-protection';
export interface AuthOptions {
    returnUrl: string;
    chsWebUrl: string;
    companyNumber?: string;
    requestScopeAndPermissions?: RequestScopeAndPermissions;
}
export interface RequestScopeAndPermissions {
    scope: string;
    tokenPermissions: IUserProfile[UserProfileKeys.TokenPermissions];
}
export declare const authMiddleware: (options: AuthOptions) => RequestHandler;
