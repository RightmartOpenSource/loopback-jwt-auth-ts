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


## Testing
For this repository doesn't exist any test.
But it is tested and used in production in a close source project


## Build

* Run `npm install`
* Run `npm run build `