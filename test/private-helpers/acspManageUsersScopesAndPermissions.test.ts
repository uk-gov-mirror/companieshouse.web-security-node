import {  assert} from 'chai'
import { getAcspManageUserScopesAndPermissions } from '../../src/private-helpers/acspManageUsersScopesAndPermissions'
import { AcspOptions } from '../../src'
import { UserRole } from '../../src/scopes-permissions/acspManageUsersAuthMiddleware'

describe('Test getAcspManageUserScopesAndPermissions function', () => {
  let acspOpts: AcspOptions
  const acspNumber = 'abc123';
  const scope = `https://api.company-information.service.gov.uk/authorized-corporate-service-provider/${acspNumber}`

  const standardUserPermissions = { 
    scope,
    tokenPermissions: {
        "acsp_members": "read",
        acsp_number: acspNumber
    }
}

const adminUserPermissions = {
    scope,
    tokenPermissions: {
        "acsp_members_admins": "create,update,delete",
        "acsp_members_standard": "create,update,delete",
        "acsp_members": "read",
        acsp_number: acspNumber
    }
}

const ownerPermissions = {
    scope,
    tokenPermissions: {
        "acsp_members_owners": "create,update,delete",
        "acsp_members_admins": "create,update,delete",
        "acsp_members_standard": "create,update,delete",
        "acsp_members": "read",
        acsp_number: acspNumber
    }
}

    it('Should return standard user permmissions when a role is not provided ', () => {
        acspOpts = {
            acspNumber,
            userRole: undefined
        }
      assert.deepEqual(getAcspManageUserScopesAndPermissions(acspOpts),standardUserPermissions)
    })
    it('Should return admin user permmissions when a role is admin ', () => {
        acspOpts = {
            acspNumber,
            userRole: UserRole.ADMIN
        }
      assert.deepEqual(getAcspManageUserScopesAndPermissions(acspOpts),adminUserPermissions)
    })  
    it('Should return owner permmissions when a role is owner ', () => {
        acspOpts = {
            acspNumber,
            userRole: UserRole.OWNER
        }
      assert.deepEqual(getAcspManageUserScopesAndPermissions(acspOpts),ownerPermissions)
    })     
  })


