import '@companieshouse/node-session-handler';
import { RequestHandler } from 'express';
export interface AuthOptions {
    returnUrl: string;
    accountWebUrl: string;
}
export declare const authMiddleware: (options: AuthOptions) => RequestHandler;
