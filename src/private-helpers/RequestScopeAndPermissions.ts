import {IUserProfile} from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import {UserProfileKeys} from '@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys'

export interface RequestScopeAndPermissions {
    scope: string
    tokenPermissions: IUserProfile[UserProfileKeys.TokenPermissions] // { [permission: string]: string }
  }