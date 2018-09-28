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
        this.idIdentifier = "internalId";
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
        this.pending = new Map();
    }
    static getHashedToken(jwtToken) {
        return sha2_1.SHA256(jwtToken).toString("hex");
    }
    static hasTokenChanged(jwtToken, user) {
        return sha2_1.SHA256(jwtToken) != user.jwtTokenHash;
    }
    deleteAfterExpired(token, exp) {
        const now = Date.now().valueOf() - JWTAuthMiddleware.STATIC_DELTA_FOR_REQUEST_PROCESSING_TIME_IN_MS;
        this.logger("token exp ", exp, now);
        setTimeout(() => this.pending.delete(token), exp * 1000 - now);
    }
    async authAvoidParallel(req) {
        let entry;
        const jwtToken = await this.getToken(req);
        if (!this.pending.has(jwtToken)) {
            this.logger("New auth request ", jwtToken);
            const promise = this.auth(req);
            this.pending.set(jwtToken, promise);
            entry = await promise;
        }
        else {
            this.logger("use existing request");
            entry = await this.pending.get(jwtToken);
        }
        req.user = entry.user;
        req.accessToken = entry.token;
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
        const userId = lodash.get(payload, this.idIdentifier, null);
        const userEmail = lodash.get(payload, this.emailIdentifier, null);
        const userRoles = lodash.get(payload, this.roleIdentifier, null);
        this.logger("Email and roles are: ", userId, userEmail, userRoles);
        if (!userId) {
            throw new Error(`JWT invalid format ${this.emailIdentifier} 
            is required in payload but was ${JSON.stringify(payload)}`);
        }
        const { user, password } = await this.getOrCreateUser(userId, userEmail, payload);
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
        this.deleteAfterExpired(jwtToken, payload.exp);
        return {
            user,
            token,
            exp: payload.exp,
        };
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
    async getOrCreateUser(userId, email, jwtPayload) {
        const password = this.passwordSecret;
        let newUser = {
            email,
            password
        };
        let where = { email };
        if (userId) {
            where = { id: userId };
        }
        newUser = Object.assign(newUser, await this.beforeUserCreate(newUser, jwtPayload));
        const user = await utils_1.saveUpsertWithWhere(this.user, where, newUser);
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
        this.authAvoidParallel(req)
            .then(() => next())
            .catch(next);
    }
}
JWTAuthMiddleware.STATIC_DELTA_FOR_REQUEST_PROCESSING_TIME_IN_MS = 1000;
exports.default = JWTAuthMiddleware;
//# sourceMappingURL=JWTAuthMiddleware.js.map