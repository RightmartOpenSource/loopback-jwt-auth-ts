"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jwt = require("jsonwebtoken");
const lodash = require("lodash");
const utils_1 = require("./utils");
const debug = require("debug");
const UnauthorizedError_1 = require("./UnauthorizedError");
const sha2_1 = require("sha2");
class JWTAuthMiddleware {
    constructor(options) {
        this.emailIdentifier = "email";
        this.roleIdentifier = "roles";
        this.beforeUserCreate = options.beforeUserCreate;
        this.verify = options.verify;
        this.getToken = options.getToken;
        this.role = options.roleModel;
        this.roleMapping = options.roleMappingModel;
        this.user = options.userModel;
        this.accessToken = options.accessToken;
        this.passwordSecret = options.passwordSecret;
        this.logger = options.logger ? options.logger : debug("loopback-jwt-auth-ts:JWTAuthMiddleware");
    }
    static createRandomPassword(email) {
        return sha2_1.SHA256(email);
    }
    static hasTokenChanged(jwtToken, user) {
        return sha2_1.SHA256(jwtToken) != user.jwtTokenHash;
    }
    static getHashedToken(jwtToken) {
        return sha2_1.SHA256(jwtToken);
    }
    async auth(req) {
        const jwtToken = await this.getToken(req);
        if (typeof jwtToken !== "string") {
            throw new UnauthorizedError_1.default("Can't find jwt in request");
        }
        this.logger("Got token from request", jwtToken);
        try {
            await this.verify(jwtToken);
        }
        catch (e) {
            throw e;
        }
        const payload = jwt.decode(jwtToken);
        this.logger("Token is valid and got payload ", payload);
        const userEmail = lodash.get(payload, this.emailIdentifier, null);
        const userRoles = lodash.get(payload, this.roleIdentifier, null);
        this.logger("Email and roles are: ", userEmail, userRoles);
        if (!userEmail) {
            throw new Error(`JWT invalid format ${this.emailIdentifier} 
            is required in payload but was ${JSON.stringify(payload)}`);
        }
        const { user, password } = await this.getOrCreateUser(userEmail, payload);
        this.logger("Created or updated User", user);
        if (userRoles && JWTAuthMiddleware.hasTokenChanged(jwtToken, user)) {
            this.logger("Updated roles ", userRoles);
            const roles = await this.ensureRolesExists(userRoles);
            await this.updateRoleMapping(user, roles);
        }
        else {
            this.logger("Skipping role update because nothing changed", user.email);
        }
        this.logger("Login and get Token");
        const token = await this.loginUser(user, password, payload);
        this.logger("Got access token ", token);
        this.logger("Role mappings: ", await this.roleMapping.find({}));
        this.logger("Roles: ", await this.role.find({}));
        this.logger("users: ", await this.user.find({}));
        await this.user.updateAll({ id: user.id }, { jwtTokenHash: JWTAuthMiddleware.getHashedToken(jwtToken) });
        req.user = user;
        req.accessToken = token;
    }
    async loginUser(user, password, jwtPayload) {
        let now = Math.round(Date.now().valueOf() / 1000);
        const ttl = jwtPayload.exp - now;
        const token = await this.user.login({
            email: user.email,
            password,
            ttl,
        });
        await this.accessToken.updateAll({ id: token.id }, { userId: user.id });
        return await this.accessToken.findById(token.id);
    }
    async getOrCreateUser(email, jwtPayload) {
        const password = this.passwordSecret;
        let newUser = {
            email,
            password
        };
        newUser = Object.assign(newUser, await this.beforeUserCreate(newUser, jwtPayload));
        const user = await utils_1.saveUpsertWithWhere(this.user, { email }, newUser);
        return {
            user,
            password,
        };
    }
    async updateRoleMapping(user, newRoles) {
        await this.roleMapping.destroyAll({ principalId: user.id });
        await Promise.all(newRoles.map(async (role) => {
            const data = {
                roleId: role.id,
                principalType: this.roleMapping['USER'],
                principalId: user.id
            };
            this.logger("Update role mapping ", data);
            await utils_1.saveUpsertWithWhere(this.roleMapping, data, data);
        }));
    }
    ensureRolesExists(roles) {
        return Promise.all(roles.map(async (role) => {
            this.logger("Update role ", role);
            const data = {
                name: role
            };
            return await utils_1.saveUpsertWithWhere(this.role, data, data);
        }));
    }
    process(req, res, next) {
        this.auth(req)
            .then(() => next())
            .catch(next);
    }
}
exports.default = JWTAuthMiddleware;
//# sourceMappingURL=JWTAuthMiddleware.js.map