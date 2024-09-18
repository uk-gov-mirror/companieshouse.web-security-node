import { AcspOptions, UserRole } from "../scopes-permissions/acspManageUsersAuthMiddleware"
import { RequestScopeAndPermissions } from './RequestScopeAndPermissions'

export const getAcspManageUserScopesAndPermissions = (acspOptions: AcspOptions): RequestScopeAndPermissions => {
    if (acspOptions.user_role === UserRole.OWNER) {
        return {
            scope: '',
            tokenPermissions: {
                "acsp_members_owners": "create,update,delete",
                "acsp_members_admins": "create,update,delete",
                "acsp_members_standard": "create,update,delete",
                "acsp_members": "read",
                "ascp_number": acspOptions.acsp_number
            }
        }
    }
    if (acspOptions.user_role === UserRole.ADMIN) {
        return {
            scope: '',
            tokenPermissions: {
                "acsp_members_admins": "create,update,delete",
                "acsp_members_standard": "create,update,delete",
                "acsp_members":"read",
                "ascp_number": acspOptions.acsp_number
            }
        }
    } else return {
            scope: '',
            tokenPermissions: {
                'acsp_profile': acspOptions.acsp_number
            }
        }
}
