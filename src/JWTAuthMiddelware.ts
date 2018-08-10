import * as jwt from "jsonwebtoken";
import * as lodash from "lodash";
import * as uuid from "uuid/v4";
import {saveUpsertWithWhere} from "./utils";
import * as crypto from "crypto";

interface User {
    id: string,
    email: string
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
    verify: (jwt: string) => Promise<boolean>
    getToken: (req: any) => Promise<string>
    beforeUserCreate: (email: string) => Promise<any>
    userModel: Model<any>
    roleModel: Model<any>
    roleMappingModel: Model<any>
    accessToken: Model<Token>;
}
export default class JWTAuthMiddelware {

    private static createRandomPassword(){
        return crypto.createHash('md5').update(uuid()).digest('hex');
    }


    role: Model<any>;
    roleMapping: Model<any>;
    user: Model<User>;
    accessToken: Model<Token>;
    verify: (jwt: string) => Promise<boolean>;
    getToken: (req: any) => Promise<string>;
    beforeUserCreate:(email: string) => Promise<any>;
    emailIdentifier: string = "email";
    roleIdentifier: string = "roles";

    constructor(options:JWTAuthMiddelwareOptions ){

        this.beforeUserCreate = options.beforeUserCreate;
        this.verify = options.verify;
        this.getToken = options.getToken;
        this.role = options.roleModel;
        this.roleMapping = options.roleMappingModel;
        this.user = options.userModel;
        this.accessToken = options.accessToken;
    }

    private async auth(req): Promise<void>{

        const jwtToken = await this.getToken(req);

        const isValid = await this.verify(jwtToken);

        if(!isValid){
            throw new Error("Invalid jwt");
        }

        const payload = jwt.getToken(jwtToken);

        const userEmail = lodash.get(payload, this.emailIdentifier, null) as string;
        const userRoles = lodash.get(payload, this.roleIdentifier, null) as string[];

        if(!userEmail){
            throw new Error(`JWT invalid format ${this.emailIdentifier} 
            is required in payload but was ${JSON.stringify(payload)}`)
        }
        const { user, password }= await this.getOrCreateUser(userEmail);

        if(userRoles){
            await this.ensureRolesExists(userRoles);
            await this.updateRoleMapping(user, userRoles);
        }

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

    private async getOrCreateUser(email): Promise<{user: User, password: string}>{

        const password = JWTAuthMiddelware.createRandomPassword();
        let newUser = {
            email,
            password
        };

        newUser = Object.assign(newUser, await this.beforeUserCreate(email));
        const user = await saveUpsertWithWhere(this.user, {email}, newUser) as User;
        return {
            user,
            password,
        }

    }
    private async updateRoleMapping(user: User, newRoles: string[]){
        const currentRoles = await this.roleMapping.find({userId: user.id});
        await this.roleMapping.destroyAll({userId: user.id});
        await Promise.all(newRoles.map(async () => {
            const data = {
                principalType: this.roleMapping['USER'],
                principalId: user.id
            };
            await  saveUpsertWithWhere(this.roleMapping, data, data)
        }));


    }

    private ensureRolesExists(roles: string[]){
        return Promise.all(roles.map(async (role: string)=> {
            return await saveUpsertWithWhere(this.role, {name: role}, {name: role})
        }))
    }
    public process(req, res, next: (err? : Error) => any) {

        this.auth(req)
        .then(next)
        .catch(next)

    }

}