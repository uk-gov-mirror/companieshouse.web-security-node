"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authMiddleware = void 0;
require("@companieshouse/node-session-handler");
const SessionKey_1 = require("@companieshouse/node-session-handler/lib/session/keys/SessionKey");
const SignInInfoKeys_1 = require("@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys");
const structured_logging_node_1 = require("@companieshouse/structured-logging-node");
const additionalScopeIsRequired_1 = require("./utils/additionalScopeIsRequired");
__exportStar(require("./csrf-protection"), exports);
const APP_NAME = 'web-security-node';
const logger = (0, structured_logging_node_1.createLogger)(APP_NAME);
const authMiddleware = (options) => (req, res, next) => {
    const appName = 'CH Web Security Node';
    if (!options.chsWebUrl) {
        logger.error(`${appName} - handler: Required Field CHS Web URL not set`);
        throw new Error('Required Field CHS Web URL not set');
    }
    let redirectURI = `${options.chsWebUrl}/signin?return_to=${options.returnUrl}`;
    if (options.companyNumber) {
        redirectURI = redirectURI.concat(`&company_number=${options.companyNumber}`);
    }
    if (!req.session) {
        if (options.requestScopeAndPermissions) {
            redirectURI = redirectURI.concat(`&additional_scope=${options.requestScopeAndPermissions.scope}`);
        }
        logger.debug(`${appName} - handler: Session object is missing!`);
        return res.redirect(redirectURI);
    }
    const signInInfo = req.session.get(SessionKey_1.SessionKey.SignInInfo) || {};
    const signedIn = signInInfo[SignInInfoKeys_1.SignInInfoKeys.SignedIn] === 1;
    const userProfile = signInInfo[SignInInfoKeys_1.SignInInfoKeys.UserProfile] || {};
    const userId = userProfile === null || userProfile === void 0 ? void 0 : userProfile.id;
    if (options.requestScopeAndPermissions && (0, additionalScopeIsRequired_1.additionalScopeIsRequired)(options.requestScopeAndPermissions, userProfile)) {
        redirectURI = redirectURI.concat(`&additional_scope=${options.requestScopeAndPermissions.scope}`);
        logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.requestScopeAndPermissions}... Updating URL to: ${redirectURI}`);
    }
    if (!signedIn) {
        logger.info(`${appName} - handler: userId=${userId}, Not signed in... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }
    if (options.companyNumber && !isAuthorisedForCompany(options.companyNumber, signInInfo)) {
        logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.companyNumber}... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }
    if (options.requestScopeAndPermissions && (0, additionalScopeIsRequired_1.additionalScopeIsRequired)(options.requestScopeAndPermissions, userProfile)) {
        logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.requestScopeAndPermissions}... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }
    logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`);
    return next();
};
exports.authMiddleware = authMiddleware;
function isAuthorisedForCompany(companyNumber, signInInfo) {
    const authorisedCompany = signInInfo[SignInInfoKeys_1.SignInInfoKeys.CompanyNumber];
    if (!authorisedCompany) {
        return false;
    }
    return authorisedCompany.localeCompare(companyNumber) === 0;
}
