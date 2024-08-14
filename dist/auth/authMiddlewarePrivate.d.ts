import '@companieshouse/node-session-handler';
import { RequestHandler } from 'express';
import { AuthOptions } from '..';
export declare const authMiddlewarePrivate: (options: AuthOptions) => RequestHandler;
