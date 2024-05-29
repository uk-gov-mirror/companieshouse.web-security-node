/**
 * Base class for all Errors raised as a result of CSRF filtering
 */
export class CsrfError extends Error {

    className(): string {
        return this.constructor.name
    }
}

/**
 * An Error thrown when CSRF token does not match the expected token held
 * within session
 */
export class CsrfTokensMismatchError extends CsrfError {
}

/**
 * An error thrown when CSRF token is not held within the Session when
 * validating a request.
 */
export class MissingCsrfSessionToken extends CsrfError { }

/**
 * A CSRF Error thrown when the session is unset
 */
export class SessionUnsetError extends CsrfError { }
