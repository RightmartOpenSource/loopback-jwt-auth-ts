# Loopback-jwt-auth-ts
This package provide a jwt authentication for a loopback 3.x.x application.

## Getting started

```
npm install https://github.com/RightmartOpenSource/loopback-jwt-auth-ts

```

```
import JWTAuthMiddleware from "loopback-jwt-auth-ts/build/index";

const auth = new JWTAuthMiddleware({
    verify: (token) => jsonwebtoken.verify(token),
    getToken: (req)=> req.heades["api-key"] ,
    beforeUserCreate: (newUser, jwtPayload) => newUser ,
    userModel: app.models.user,
    roleModel: app.models.Role,
    roleMappingModel: app.models.RoleMapping,
    accessToken: app.models.AccessToken,

  });

```

Before creating a new user or updating an existing one, the existence is determined by the
information profided with the JWT tocken. The existence is checked with the email address or the
internalId from the tocken. An internalId is prefered over an email address.

## Testing
For this repository doesn't exist any test.
But it is tested and used in production in a close source project


## Build

* Run `npm install`
* Run `npm run build `