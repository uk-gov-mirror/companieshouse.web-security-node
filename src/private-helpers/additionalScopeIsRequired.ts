import { IUserProfile } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import { UserProfileKeys } from '@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys'
import { RequestScopeAndPermissions } from './RequestScopeAndPermissions'

// return TRUE if
//   (1) any key in requestScopeAndPermissions.tokenPermissions object is missing from userProfile.tokenPermissions object, OR
//   (2) a value of a key in requestScopeAndPermissions.tokenPermissions object is not in the corresponding value of the same
//       key in userProfile.tokenPermissions
// note for (2) we would need to map values "create,update,etc" => "create", "update", "etc" to get individual values
export function additionalScopeIsRequired(requestScopeAndPermissions: RequestScopeAndPermissions | undefined | null, userProfile: IUserProfile): boolean {

  // user has not specified any scopes
  if (!requestScopeAndPermissions) {
    return false;
  }

  if (!userProfile.hasOwnProperty(UserProfileKeys.TokenPermissions)) {
    return true;
  }

  const userProfileTokenPermissions = userProfile[UserProfileKeys.TokenPermissions];

  // belt and braces
  if (userProfileTokenPermissions == null) {
    return true;
  }

  // check each requested key is in the user profile
  for (const key in requestScopeAndPermissions.tokenPermissions) {

    if (!userProfileTokenPermissions.hasOwnProperty(key)) {
      return true; // key is missing in userProfile, so since we request this permission we will need to add it
    }

    const requestValue = requestScopeAndPermissions.tokenPermissions[key];
    const userProfileValue = userProfileTokenPermissions[key];

    // split, sort, and join the values to compare them irrespective of order
    const normaliseCommaSeparatedString = (value: string): string => {
      return value
        .split(',')                     // Split the string by commas
        .map(item => item.trim())       // Trim whitespace from each item
        .filter(item => item !== '')    // Remove any empty strings
        .sort()                         // Sort the array alphabetically
        .join(',');                     // Join the array back into a string
    };

    const requestArray = normaliseCommaSeparatedString(requestValue);
    const userProfileArray = normaliseCommaSeparatedString(userProfileValue);

    if ( ! userProfileArray.includes(requestArray)) {
      return true; // user profile does not have all the permissions for the requested key
    }
  }

  return false;
}
