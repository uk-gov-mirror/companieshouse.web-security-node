"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.additionalScopeIsRequired = void 0;
const UserProfileKeys_1 = require("@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys");
function additionalScopeIsRequired(requestScopeAndPermissions, userProfile) {
    if (!requestScopeAndPermissions) {
        return false;
    }
    if (!userProfile.hasOwnProperty(UserProfileKeys_1.UserProfileKeys.TokenPermissions)) {
        return true;
    }
    const userProfileTokenPermissions = userProfile[UserProfileKeys_1.UserProfileKeys.TokenPermissions];
    if (userProfileTokenPermissions == null) {
        return true;
    }
    for (const key in requestScopeAndPermissions.tokenPermissions) {
        if (!userProfileTokenPermissions.hasOwnProperty(key)) {
            return true;
        }
        const requestValue = requestScopeAndPermissions.tokenPermissions[key];
        const userProfileValue = userProfileTokenPermissions[key];
        const normaliseCommaSeparatedString = (value) => {
            return value
                .split(',')
                .map(item => item.trim())
                .filter(item => item !== '')
                .sort()
                .join(',');
        };
        const requestArray = normaliseCommaSeparatedString(requestValue);
        const userProfileArray = normaliseCommaSeparatedString(userProfileValue);
        if (!userProfileArray.includes(requestArray)) {
            return true;
        }
    }
    return false;
}
exports.additionalScopeIsRequired = additionalScopeIsRequired;
