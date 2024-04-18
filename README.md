# web-security-node
Security for web applications in node

## `CsrfProtectionMiddleware`

Express middleware which will protect an application from Cross Site Request
Forgery (CSRF) attacks. The middleware works by looking for a token within the
request which should match a token held within the CHS session. The middleware
will expect all requests from methods which modify data (for example
`POST`/`DELETE`/`PUT`) to include the CSRF token. This implements a
[Synchronisation Token Pattern approach](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern)

### Installation instructions

1. Install the library (if not already installed).

    ```sh
    npm i @companieshouse/web-security-node@^3.0.0
    ```

2. Define the options for the middleware and add the middleware to the
  application

    ```typescript
    import { CsrfProtectionMiddleware } from " @companieshouse/web-security-node"
    import {
        SessionStore,
        SessionMiddleware
    } from '@companieshouse/node-session-handler';
    import express from "express";
    import cookieParser from 'cookie-parser';
    import Redis from 'ioredis';
    

    const app = express();
    
    // apply other middlewares

    app.use(cookieParser());
    const cookieName = '__SID'

    const cookieConfig = {
        cookieName,
        cookieSecret: config.COOKIE_SECRET,
        cookieDomain: config.COOKIE_DOMAIN,
        cookieTimeToLiveInSeconds: parseInt(config.DEFAULT_SESSION_EXPIRATION, 10)
    };
    const sessionStore = new SessionStore(new Redis(`redis://${config.CACHE_SERVER}`));
    // Important the session Middleware is required before this middleware since the
    // token is stored within the session
    app.use(SessionMiddleware(cookieConfig, sessionStore));
    const csrfMiddlewareOptions = {
        sessionStore,
        enabled: true,
        sessionCookieName: cookieName
    }
    app.use(CsrfProtectionMiddleware(csrfMiddlewareOptions))

    ```

3. In each form which submits data (or modifies data) add the following macro call

    ```nunjucks
    {% from "web-security-node/components/csrf-token-input/macro.njk" import csrfTokenInput %}

    <form action="POST">
        {{
            csrfTokenInput({
                csrfToken: csrfToken
            })
        }}
        <!-- Other form items ommitted -->
    </form>
    ```

### API

#### `CsrfOptions` interface

Provides configuration to the middleware.

##### Properties

* `enabled` (*boolean* **required**) - whether or not to apply CSRF protections
* `sessionStore` (*SessionStore* **required**) - a SessionStore instance to
  manage the CHS session
* `sessionCookieName` (*string*) - name of the cookie storing the signed
  Session ID
* `csrfTokenFactory` (*supplier of string*) - a callable when called will
  return a string to use as the session's CSRF token. Has signature:

    ```typescript
    () => string
    ```

    Defaults to a uuid supplier if not supplied.

* `createWhenCsrfTokenAbsent` (*boolean*) - whether to generate a new CSRF
  token if not present in the session. Only run on non-mutable requests (e.g. 
  GET)
* `headerName` (*string*) - name of the header to check. Defaults to
  `X-CSRF-TOKEN`
* `parameterName` (*string*) - name of the parameter in the request body to
  check. Defaults to `_csrf`.

#### `CsrfProtectionMiddleware` function

A Request Handler capable of being used as a express Middleware function. Its
responsibility is checking that all mutable requests include a csrf token which
indicates that they originated from the same CHS session and not an CSRF
attempt. The middleware expects that all mutable requests contain a token which
matches a token stored within the CHS session.

##### Parameters

* `options` - (*CsrfOptions* **required**) - the configuration for the
  middleware is provided as an object which implements the interface
  `CsrfOptions`

#### `defaultCsrfTokenFactory` function

This function is the default CSRF issuing function, it essentially provides an

#### Exceptions

**`CsrfTokensMismatchError`** - Thrown when the CSRF token is either missing
in the mutable request or does not match the CSRF token within the CHS session.

**`MissingCsrfSessionToken`** - Thrown when there is no CSRF token within the
session to match the request's Token against.
