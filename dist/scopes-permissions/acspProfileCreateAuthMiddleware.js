"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.acspProfileCreateAuthMiddleware = void 0;
const __1 = require("../");
const acspProfileCreateAuthMiddleware = (options) => (req, res, next) => {
    const authMiddlewareConfig = {
        chsWebUrl: options.chsWebUrl,
        returnUrl: options.returnUrl,
        requestScopeAndPermissions: {
            scope: 'https://identity.company-information.service.gov.uk/acsp-profile.create',
            tokenPermissions: {
                'acsp_profile': 'create'
            }
        }
    };
    return (0, __1.authMiddleware)(authMiddlewareConfig)(req, res, next);
};
exports.acspProfileCreateAuthMiddleware = acspProfileCreateAuthMiddleware;
