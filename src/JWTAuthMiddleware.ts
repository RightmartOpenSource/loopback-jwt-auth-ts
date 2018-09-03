import * as jwt from "jsonwebtoken";
import * as lodash from "lodash";
import {saveUpsertWithWhere} from "./utils";
import * as debug from "debug";
import UnauthorizedError from "./UnauthorizedError";
import {SHA256} from "sha2"

interface Role {
    id: string,
    name: string
}

interface User {
    id?: string,
    email: string
    password: string,
    jwtTokenHash: string
}
interface Token {
    id: string,
    userId: string,
}
interface Model<T>{
    findById(id:string): Promise<T>
    upsertWithWhere(filter, data): Promise<T>
    find(filter: any): Promise<void>
    destroyAll(where: any): Promise<void>
    updateAll(where: any, data: any): Promise<void>
    login(data: any): Promise<Token>
}
interface JWTAuthMiddelwareOptions{
    verify: (jwt: string) => Promise<any>
    getToken: (req: any) => Promise<string>
    beforeUserCreate: (newUser: User, jwtPayload: any) => Promise<any>
    userModel: Model<any> | any
    roleModel: Model<any> | any
    roleMappingModel: Model<any> | any
    accessToken: Model<Token> | any;
    logger?: (...args)=> void
    passwordSecret: string;
}
export default class JWTAuthMiddleware {
    public static getHashedToken(jwtToken: string) {
        return SHA256(jwtToken).toString("hex");
    }

    private static readonly STATIC_DELTA_FOR_REQUEST_PROCESSING_TIME_IN_MS = 1000;

    private static hasTokenChanged(jwtToken: string, user: User){

        return  SHA256(jwtToken) != user.jwtTokenHash
    }

    role: Model<any>;
    roleMapping: Model<any>;
    user: Model<User>;
    accessToken: Model<Token>;
    verify: (jwt: string) => Promise<any>;
    getToken: (req: any) => Promise<string>;
    beforeUserCreate:(newUser: User, jwtPayload: any) => Promise<any>;
    emailIdentifier: string = "email";
    idIdentifier: string = "internalId";
    roleIdentifier: string = "roles";
    passwordSecret: string;
    logger: (...args)=> void;
    pending: Map<string, Promise<{user: User, token: Token}>>;


    constructor(options:JWTAuthMiddelwareOptions ){

        this.beforeUserCreate = options.beforeUserCreate;
        this.verify = options.verify;
        this.getToken = options.getToken;
        this.role = options.roleModel;
        this.roleMapping = options.roleMappingModel;
        this.user = options.userModel;
        this.accessToken = options.accessToken;
        this.passwordSecret = options.passwordSecret;
        this.logger = options.logger ? options.logger : debug("loopback-jwt-auth-ts:JWTAuthMiddleware")
        this.pending = new Map();
    }

    deleteAfterExpired(token, exp) {
        const now = Date.now().valueOf() - JWTAuthMiddleware.STATIC_DELTA_FOR_REQUEST_PROCESSING_TIME_IN_MS;
        this.logger("token exp ", exp, now)
        setTimeout(() => this.pending.delete(token), exp - now/1000);
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

    private async auth(req): Promise<{user: User, token: Token, exp: Number}>{

        const jwtToken = await this.getToken(req);

        if(typeof jwtToken !== "string"){
            throw new UnauthorizedError("Can't find jwt in request");
        }
        this.logger("Got token from request", jwtToken);

        try {
            await this.verify(jwtToken);

        }catch (e) {
            throw e;
        }

        const payload = jwt.decode(jwtToken);

        this.logger("Token is valid and got payload ", payload);

        const userId = lodash.get(payload, this.idIdentifier, null) as string;
        const userEmail = lodash.get(payload, this.emailIdentifier, null) as string;
        const userRoles = lodash.get(payload, this.roleIdentifier, null) as string[];

        this.logger("Email and roles are: ", userId, userEmail, userRoles);

        if(!userId){
            throw new Error(`JWT invalid format ${this.emailIdentifier} 
            is required in payload but was ${JSON.stringify(payload)}`)
        }
        const { user, password }= await this.getOrCreateUser(userId, userEmail, payload);

        this.logger("Created or updated User", user);

        if(userRoles && JWTAuthMiddleware.hasTokenChanged(jwtToken, user) ){
            this.logger("Updated roles ", userRoles);
            const roles = await this.ensureRolesExists(userRoles);
            await this.updateRoleMapping(user, roles);
        }else {
            this.logger("Skipping role update because nothing changed", user.email);
        }

        this.logger("Login and get Token");
        const token = await this.loginUser(user,password,payload);

        this.logger("Got access token ", token);

        this.logger("Role mappings: ", await this.roleMapping.find({}));
        this.logger("Roles: ", await this.role.find({}));
        this.logger("users: ", await this.user.find({}));

        // save hash of token to skip role update next time
        await this.user.updateAll({id: user.id}, {jwtTokenHash: JWTAuthMiddleware.getHashedToken(jwtToken)});

        this.deleteAfterExpired(jwtToken, payload.exp);

        return {
            user,
            token,
            exp: payload.exp,
        };

    }



    private async loginUser(user: User, password: string, jwtPayload: any): Promise<Token>{
        let now = Math.round(Date.now().valueOf()/1000);
        const ttl = jwtPayload.exp - now;
        const token = await this.user.login({
            email: user.email,
            password,
            ttl,
        });
        await this.accessToken.updateAll({id: token.id}, { userId: user.id });

        return await this.accessToken.findById(token.id);
    }

    private async getOrCreateUser(userId, email, jwtPayload: any): Promise<{user: User, password: string}>{

        const password = this.passwordSecret;
        let newUser = {
            email,
            password
        } as User;

        let where: any = { email }
        if (userId) {
            where = { id: userId };
        }

        newUser = Object.assign(newUser, await this.beforeUserCreate(newUser, jwtPayload));
        const user = await saveUpsertWithWhere(this.user, where, newUser) as User;
        return {
            user,
            password,
        }

    }
    private async updateRoleMapping(user: User, newRoles: Role[]){
        await this.roleMapping.destroyAll({principalId: user.id});
        await Promise.all(newRoles.map(async (role) => {
            const data = {
                roleId: role.id,
                principalType: this.roleMapping['USER'],
                principalId: user.id
            };
            this.logger("Update role mapping ", data);
            await  saveUpsertWithWhere(this.roleMapping, data, data)
        }));


    }

    private ensureRolesExists(roles: string[]) : Promise<Role[]>{
        return Promise.all(roles.map(async (role: string)=> {
            this.logger("Update role ", role);
            const data = {
                name: role
            };
            return await saveUpsertWithWhere(this.role, data, data)
        }))
    }
    public process(req, res, next: (err? : Error) => any) {

        this.authAvoidParallel(req)
            .then(() => next())
            .catch(next)

    }

}