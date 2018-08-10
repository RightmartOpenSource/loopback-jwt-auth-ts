"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var jwt = require("jsonwebtoken");
var lodash = require("lodash");
var uuid = require("uuid/v4");
var utils_1 = require("./utils");
var debug = require("debug");
var JWTAuthMiddleware = /** @class */ (function () {
    function JWTAuthMiddleware(options) {
        this.emailIdentifier = "email";
        this.roleIdentifier = "roles";
        this.beforeUserCreate = options.beforeUserCreate;
        this.verify = options.verify;
        this.getToken = options.getToken;
        this.role = options.roleModel;
        this.roleMapping = options.roleMappingModel;
        this.user = options.userModel;
        this.accessToken = options.accessToken;
        this.logger = options.logger ? options.logger : debug("loopback-jwt-auth-ts:JWTAuthMiddleware");
    }
    JWTAuthMiddleware.createRandomPassword = function () {
        return uuid();
    };
    JWTAuthMiddleware.prototype.auth = function (req) {
        return __awaiter(this, void 0, void 0, function () {
            var jwtToken, e_1, payload, userEmail, userRoles, _a, user, password, roles, token, _b, _c, _d, _e, _f, _g;
            return __generator(this, function (_h) {
                switch (_h.label) {
                    case 0: return [4 /*yield*/, this.getToken(req)];
                    case 1:
                        jwtToken = _h.sent();
                        this.logger("Got token from request", jwtToken);
                        _h.label = 2;
                    case 2:
                        _h.trys.push([2, 4, , 5]);
                        return [4 /*yield*/, this.verify(jwtToken)];
                    case 3:
                        _h.sent();
                        return [3 /*break*/, 5];
                    case 4:
                        e_1 = _h.sent();
                        throw e_1;
                    case 5:
                        payload = jwt.decode(jwtToken);
                        this.logger("Token is valid and got payload ", payload);
                        userEmail = lodash.get(payload, this.emailIdentifier, null);
                        userRoles = lodash.get(payload, this.roleIdentifier, null);
                        this.logger("Email and roles are: ", userEmail, userRoles);
                        if (!userEmail) {
                            throw new Error("JWT invalid format " + this.emailIdentifier + " \n            is required in payload but was " + JSON.stringify(payload));
                        }
                        return [4 /*yield*/, this.getOrCreateUser(userEmail, payload)];
                    case 6:
                        _a = _h.sent(), user = _a.user, password = _a.password;
                        this.logger("Created or updated User", user);
                        if (!userRoles) return [3 /*break*/, 9];
                        this.logger("Updated roles ", userRoles);
                        return [4 /*yield*/, this.ensureRolesExists(userRoles)];
                    case 7:
                        roles = _h.sent();
                        return [4 /*yield*/, this.updateRoleMapping(user, roles)];
                    case 8:
                        _h.sent();
                        _h.label = 9;
                    case 9:
                        this.logger("Login and get Token");
                        return [4 /*yield*/, this.loginUser(user, password, payload)];
                    case 10:
                        token = _h.sent();
                        this.logger("Got access token ", token);
                        _b = this.logger;
                        _c = ["Role mappings: "];
                        return [4 /*yield*/, this.roleMapping.find({})];
                    case 11:
                        _b.apply(this, _c.concat([_h.sent()]));
                        _d = this.logger;
                        _e = ["Roles: "];
                        return [4 /*yield*/, this.role.find({})];
                    case 12:
                        _d.apply(this, _e.concat([_h.sent()]));
                        _f = this.logger;
                        _g = ["users: "];
                        return [4 /*yield*/, this.user.find({})];
                    case 13:
                        _f.apply(this, _g.concat([_h.sent()]));
                        req.user = user;
                        req.accessToken = token;
                        return [2 /*return*/];
                }
            });
        });
    };
    JWTAuthMiddleware.prototype.loginUser = function (user, password, jwtPayload) {
        return __awaiter(this, void 0, void 0, function () {
            var now, ttl, token;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        now = Math.round(Date.now().valueOf() / 1000);
                        ttl = jwtPayload.exp - now;
                        return [4 /*yield*/, this.user.login({
                                email: user.email,
                                password: password,
                                ttl: ttl,
                            })];
                    case 1:
                        token = _a.sent();
                        return [4 /*yield*/, this.accessToken.updateAll({ id: token.id }, { userId: user.id })];
                    case 2:
                        _a.sent();
                        return [4 /*yield*/, this.accessToken.findById(token.id)];
                    case 3: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    JWTAuthMiddleware.prototype.getOrCreateUser = function (email, jwtPayload) {
        return __awaiter(this, void 0, void 0, function () {
            var password, newUser, _a, _b, _c, user;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        password = JWTAuthMiddleware.createRandomPassword();
                        newUser = {
                            email: email,
                            password: password
                        };
                        _b = (_a = Object).assign;
                        _c = [newUser];
                        return [4 /*yield*/, this.beforeUserCreate(newUser, jwtPayload)];
                    case 1:
                        newUser = _b.apply(_a, _c.concat([_d.sent()]));
                        return [4 /*yield*/, utils_1.saveUpsertWithWhere(this.user, { email: email }, newUser)];
                    case 2:
                        user = _d.sent();
                        return [2 /*return*/, {
                                user: user,
                                password: password,
                            }];
                }
            });
        });
    };
    JWTAuthMiddleware.prototype.updateRoleMapping = function (user, newRoles) {
        return __awaiter(this, void 0, void 0, function () {
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.roleMapping.destroyAll({ principalId: user.id })];
                    case 1:
                        _a.sent();
                        return [4 /*yield*/, Promise.all(newRoles.map(function (role) { return __awaiter(_this, void 0, void 0, function () {
                                var data;
                                return __generator(this, function (_a) {
                                    switch (_a.label) {
                                        case 0:
                                            data = {
                                                roleId: role.id,
                                                principalType: this.roleMapping['USER'],
                                                principalId: user.id
                                            };
                                            this.logger("Update role mapping ", data);
                                            return [4 /*yield*/, utils_1.saveUpsertWithWhere(this.roleMapping, data, data)];
                                        case 1:
                                            _a.sent();
                                            return [2 /*return*/];
                                    }
                                });
                            }); }))];
                    case 2:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    JWTAuthMiddleware.prototype.ensureRolesExists = function (roles) {
        var _this = this;
        return Promise.all(roles.map(function (role) { return __awaiter(_this, void 0, void 0, function () {
            var data;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        this.logger("Update role ", role);
                        data = {
                            name: role,
                            id: role,
                        };
                        return [4 /*yield*/, utils_1.saveUpsertWithWhere(this.role, data, data)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        }); }));
    };
    JWTAuthMiddleware.prototype.process = function (req, res, next) {
        this.auth(req)
            .then(function () { return next(); })
            .catch(next);
    };
    return JWTAuthMiddleware;
}());
exports.default = JWTAuthMiddleware;
//# sourceMappingURL=JWTAuthMiddleware.js.map