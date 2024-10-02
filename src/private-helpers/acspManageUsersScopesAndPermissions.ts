import { AcspOptions, UserRole } from "../scopes-permissions/acspManageUsersAuthMiddleware"
import { RequestScopeAndPermissions } from './RequestScopeAndPermissions'

/*  Returns the scopes and permissions required for ACSP members.
    It a role is not provided in acspOptions, the default acsp_members read permission
    is returned. This is the equilivant of standard user permissions, all ACSP members should 
    have this.
*/

export const getAcspManageUserScopesAndPermissions = (acspOptions: AcspOptions): RequestScopeAndPermissions => {
    const scope = `https://api.company-information.service.gov.uk/authorized-corporate-service-provider/${acspOptions.acspNumber}`
    const { acspNumber, userRole } = acspOptions;

    if (userRole === UserRole.OWNER) {
        return {
            scope,
            tokenPermissions: {
                "acsp_members_owners": "create,update,delete",
                "acsp_members_admins": "create,update,delete",
                "acsp_members_standard": "create,update,delete",
                "acsp_members": "read",
                acsp_number: acspNumber
            }
        }
    }
    if (userRole === UserRole.ADMIN) {
        return {
            scope,
            tokenPermissions: {
                "acsp_members_admins": "create,update,delete",
                "acsp_members_standard": "create,update,delete",
                "acsp_members": "read",
                acsp_number: acspNumber
            }
        }
    }
    return {
        scope,
        tokenPermissions: {
            "acsp_members": "read",
            acsp_number: acspNumber
        }
    }
}
