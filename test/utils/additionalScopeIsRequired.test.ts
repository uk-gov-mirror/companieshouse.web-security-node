import { IUserProfile } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import { UserProfileKeys } from '@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys'
import { assert, expect } from 'chai'
import { AuthOptions } from '../../src'
import { additionalScopeIsRequired } from '../../src/utils/additionalScopeIsRequired'

describe('Test tokenPermissionsPresent function', () => {
  let options: AuthOptions
  let userProfile: IUserProfile

  beforeEach(() => {

    options = {
      returnUrl: 'origin',
      chsWebUrl: 'accounts',
      companyNumber: '12345678',
      requestScopeAndPermissions: {
        scope: "test_scope",
        tokenPermissions: {
          "test_permission": "create,update"
        }
      }
    }

    userProfile = {
      [UserProfileKeys.TokenPermissions]: {
        "overseas_entities": "create,update,delete",
        "user_orders": "create,read,update,delete",
        "acsp_profile": "create"
      }

    }
  })

    it('When the requestScopeAndPermissions is undefined, return false', () => {

      assert(!additionalScopeIsRequired(undefined, {}))
      assert(!additionalScopeIsRequired(null, {}))
    })

    it('When the userProfile tokenPermissions is not present, return true', () => {
      assert(additionalScopeIsRequired(options.requestScopeAndPermissions, {}))
    })

    it('When the requestScopeAndPermissions tokenPermissions contains a key not present in userProfile tokenPermissions, return true', () => {
      assert(additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile))
    })

    it('When the requestScopeAndPermissions tokenPermissions contains a key in userProfile tokenPermissions, but the userProfile token permission lacks a request value, return true', () => {
      userProfile = {
        [UserProfileKeys.TokenPermissions]: {
          "overseas_entities": "create,update,delete",
          "user_orders": "create,read,update,delete",
          "acsp_profile": "create",
          "test_permission": "create"  // missing update
        }
      }
      assert(additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile))
    })

    it('When the requestScopeAndPermissions tokenPermissions contains a key in userProfile tokenPermissions and the corresponding userProfile token permission request value matches, return false', () => {
      userProfile = {
        [UserProfileKeys.TokenPermissions]: {
          "overseas_entities": "create,update,delete",
          "user_orders": "create,read,update,delete",
          "acsp_profile": "create",
          "test_permission": "create,update"
        }
      }
      assert( ! additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile))

    })

    it('When the requestScopeAndPermissions tokenPermissions contains a key in userProfile tokenPermissions and the corresponding userProfile token permission request value matches (but in wrong order and has spaces), return false', () => {
      userProfile = {
        [UserProfileKeys.TokenPermissions]: {
          "overseas_entities": "create,update,delete",
          "user_orders": "create,read,update,delete",
          "acsp_profile": "create",
          "test_permission": "update , create"
        }
      }
      assert( ! additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile))

    })


    it('When the requestScopeAndPermissions tokenPermissions contains a key in userProfile tokenPermissions and the corresponding userProfile token permission request value matches (request permissions in different order), return false', () => {
      userProfile = {
        [UserProfileKeys.TokenPermissions]: {
          "overseas_entities": "create,update,delete",
          "user_orders": "create,read,update,delete",
          "acsp_profile": "create",
          "test_permission": "create,update"
        }
      }
      if (options.requestScopeAndPermissions) {
         options.requestScopeAndPermissions.tokenPermissions = { "test_permission": "update,create" }

         assert( ! additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile))
      } else {
        expect.fail("has test data been changed ?");
      }

    })

    it('When the requestScopeAndPermissions tokenPermissions contains a key in userProfile tokenPermissions, but the userProfile token permission is null, return true', () => {
      userProfile = {
        [UserProfileKeys.TokenPermissions]: null
      }
      assert(additionalScopeIsRequired(options.requestScopeAndPermissions, userProfile))
    })
  })

