"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authMiddlewareHelper = void 0;
require("@companieshouse/node-session-handler");
const SessionKey_1 = require("@companieshouse/node-session-handler/lib/session/keys/SessionKey");
const SignInInfoKeys_1 = require("@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys");
const UserProfileKeys_1 = require("@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys");
const additionalScopeIsRequired_1 = require("./additionalScopeIsRequired");
const createLogger_1 = require("./createLogger");
const authMiddlewareHelper = (options, requestScopeAndPermissions) => (req, res, next) => {
    const appName = createLogger_1.LOG_MESSAGE_APP_NAME;
    createLogger_1.logger.debug(`${appName} - handler: in auth helper function`);
    if (!options.chsWebUrl) {
        createLogger_1.logger.error(`${appName} - handler: Required Field CHS Web URL not set`);
        throw new Error('Required Field CHS Web URL not set');
    }
    let redirectURI = `${options.chsWebUrl}/signin?return_to=${options.returnUrl}`;
    if (options.companyNumber) {
        redirectURI = redirectURI.concat(`&company_number=${options.companyNumber}`);
    }
    if (!req.session) {
        if (requestScopeAndPermissions) {
            redirectURI = redirectURI.concat(`&additional_scope=${requestScopeAndPermissions.scope}`);
        }
        createLogger_1.logger.debug(`${appName} - handler: Session object is missing!`);
        return res.redirect(redirectURI);
    }
    const signInInfo = req.session.get(SessionKey_1.SessionKey.SignInInfo) || {};
    const signedIn = signInInfo[SignInInfoKeys_1.SignInInfoKeys.SignedIn] === 1;
    const userProfile = signInInfo[SignInInfoKeys_1.SignInInfoKeys.UserProfile] || {};
    const userId = userProfile === null || userProfile === void 0 ? void 0 : userProfile.id;
    if (requestScopeAndPermissions && (0, additionalScopeIsRequired_1.additionalScopeIsRequired)(requestScopeAndPermissions, userProfile, userId)) {
        redirectURI = redirectURI.concat(`&additional_scope=${requestScopeAndPermissions.scope}`);
        createLogger_1.logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${requestScopeAndPermissions}... Updating URL to: ${redirectURI}`);
    }
    if (!signedIn) {
        createLogger_1.logger.info(`${appName} - handler: userId=${userId}, Not signed in... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }
    if (options.companyNumber && !isAuthorisedForCompany(options.companyNumber, signInInfo)) {
        createLogger_1.logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.companyNumber}... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }
    if (requestScopeAndPermissions && (0, additionalScopeIsRequired_1.additionalScopeIsRequired)(requestScopeAndPermissions, userProfile)) {
        createLogger_1.logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${requestScopeAndPermissions}... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }
    createLogger_1.logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`);
    if (userProfile.hasOwnProperty(UserProfileKeys_1.UserProfileKeys.TokenPermissions)) {
        const userProfileTokenPermissions = userProfile[UserProfileKeys_1.UserProfileKeys.TokenPermissions];
        createLogger_1.logger.debug(`${appName} : userId=${userId}, userProfileTokenPermissions are ${userProfileTokenPermissions}`);
    }
    else {
        createLogger_1.logger.debug(`${appName} : userId=${userId}, No userProfileTokenPermissions present`);
    }
    return next();
};
exports.authMiddlewareHelper = authMiddlewareHelper;
function isAuthorisedForCompany(companyNumber, signInInfo) {
    const authorisedCompany = signInInfo[SignInInfoKeys_1.SignInInfoKeys.CompanyNumber];
    if (!authorisedCompany) {
        return false;
    }
    return authorisedCompany.localeCompare(companyNumber) === 0;
}
