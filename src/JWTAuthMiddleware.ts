import * as jwt from "jsonwebtoken";
import * as lodash from "lodash";
import * as uuid from "uuid/v4";
import {saveUpsertWithWhere} from "./utils";
import * as debug from "debug";


interface User {
    id?: string,
    email: string
    password: string
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
}
export default class JWTAuthMiddleware {

    private static createRandomPassword(){
        return uuid();
    }


    role: Model<any>;
    roleMapping: Model<any>;
    user: Model<User>;
    accessToken: Model<Token>;
    verify: (jwt: string) => Promise<any>;
    getToken: (req: any) => Promise<string>;
    beforeUserCreate:(newUser: User, jwtPayload: any) => Promise<any>;
    emailIdentifier: string = "email";
    roleIdentifier: string = "roles";
    logger: (...args)=> void


    constructor(options:JWTAuthMiddelwareOptions ){

        this.beforeUserCreate = options.beforeUserCreate;
        this.verify = options.verify;
        this.getToken = options.getToken;
        this.role = options.roleModel;
        this.roleMapping = options.roleMappingModel;
        this.user = options.userModel;
        this.accessToken = options.accessToken;
        this.logger = options.logger ? options.logger : debug("loopback-jwt-auth-ts:JWTAuthMiddleware")
    }

    private async auth(req): Promise<void>{

        const jwtToken = await this.getToken(req);
        this.logger("Got token from request", jwtToken);

        try {
            await this.verify(jwtToken);

        }catch (e) {
            throw e;
        }

        const payload = jwt.decode(jwtToken);

        this.logger("Token is valid and got payload ", payload);

        const userEmail = lodash.get(payload, this.emailIdentifier, null) as string;
        const userRoles = lodash.get(payload, this.roleIdentifier, null) as string[];

        this.logger("Email and roles are: ", userEmail, userRoles);

        if(!userEmail){
            throw new Error(`JWT invalid format ${this.emailIdentifier} 
            is required in payload but was ${JSON.stringify(payload)}`)
        }
        const { user, password }= await this.getOrCreateUser(userEmail, payload);

        this.logger("Created or updated User", user);

        if(userRoles){
            this.logger("Updated roles ", userRoles);
            await this.ensureRolesExists(userRoles);
            await this.updateRoleMapping(user, userRoles);
        }

        this.logger("Login and get Token");
        const token = await this.loginUser(user,password,payload);


        req.user = user;
        req.access_token = token;

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

    private async getOrCreateUser(email, jwtPayload: any): Promise<{user: User, password: string}>{

        const password = JWTAuthMiddleware.createRandomPassword();
        let newUser = {
            email,
            password
        } as User;

        newUser = Object.assign(newUser, await this.beforeUserCreate(newUser, jwtPayload));
        const user = await saveUpsertWithWhere(this.user, {email}, newUser) as User;
        return {
            user,
            password,
        }

    }
    private async updateRoleMapping(user: User, newRoles: string[]){
        await this.roleMapping.destroyAll({principalId: user.id});
        await Promise.all(newRoles.map(async () => {
            const data = {
                principalType: this.roleMapping['USER'],
                principalId: user.id
            };
            this.logger("Update role mapping ", data);
            await  saveUpsertWithWhere(this.roleMapping, data, data)
        }));


    }

    private ensureRolesExists(roles: string[]){
        return Promise.all(roles.map(async (role: string)=> {
            this.logger("Update role ", role);
            return await saveUpsertWithWhere(this.role, {name: role}, {name: role})
        }))
    }
    public process(req, res, next: (err? : Error) => any) {

        this.auth(req)
        .then(() => next())
        .catch(next)

    }

}