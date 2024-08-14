"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authMiddlewarePrivate = void 0;
require("@companieshouse/node-session-handler");
const SessionKey_1 = require("@companieshouse/node-session-handler/lib/session/keys/SessionKey");
const SignInInfoKeys_1 = require("@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys");
const structured_logging_node_1 = require("@companieshouse/structured-logging-node");
const utils_1 = require("../utils");
const APP_NAME = 'web-security-node';
const logger = (0, structured_logging_node_1.createLogger)(APP_NAME);
const authMiddlewarePrivate = (options) => (req, res, next) => {
    const appName = 'CH Web Security Node';
    logger.debug(`${appName} - handler: in private function`);
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
    if (options.requestScopeAndPermissions && (0, utils_1.additionalScopeIsRequired)(options.requestScopeAndPermissions, userProfile)) {
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
    if (options.requestScopeAndPermissions && (0, utils_1.additionalScopeIsRequired)(options.requestScopeAndPermissions, userProfile)) {
        logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.requestScopeAndPermissions}... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }
    logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`);
    return next();
};
exports.authMiddlewarePrivate = authMiddlewarePrivate;
function isAuthorisedForCompany(companyNumber, signInInfo) {
    const authorisedCompany = signInInfo[SignInInfoKeys_1.SignInInfoKeys.CompanyNumber];
    if (!authorisedCompany) {
        return false;
    }
    return authorisedCompany.localeCompare(companyNumber) === 0;
}
