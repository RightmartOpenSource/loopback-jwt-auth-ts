interface User {
    id?: string;
    email: string;
    password: string;
    jwtTokenHash: string;
}
interface Token {
    id: string;
    userId: string;
}
interface Model<T> {
    findById(id: string): Promise<T>;
    upsertWithWhere(filter: any, data: any): Promise<T>;
    find(filter: any): Promise<void>;
    destroyAll(where: any): Promise<void>;
    updateAll(where: any, data: any): Promise<void>;
    login(data: any): Promise<Token>;
}
interface JWTAuthMiddelwareOptions {
    verify: (jwt: string) => Promise<any>;
    getToken: (req: any) => Promise<string>;
    beforeUserCreate: (newUser: User, jwtPayload: any) => Promise<any>;
    userModel: Model<any> | any;
    roleModel: Model<any> | any;
    roleMappingModel: Model<any> | any;
    accessToken: Model<Token> | any;
    logger?: (...args: any[]) => void;
    passwordSecret: string;
}
export default class JWTAuthMiddleware {
    static getHashedToken(jwtToken: string): any;
    private static readonly STATIC_DELTA_FOR_REQUEST_PROCESSING_TIME_IN_MS;
    private static hasTokenChanged;
    role: Model<any>;
    roleMapping: Model<any>;
    user: Model<User>;
    accessToken: Model<Token>;
    verify: (jwt: string) => Promise<any>;
    getToken: (req: any) => Promise<string>;
    beforeUserCreate: (newUser: User, jwtPayload: any) => Promise<any>;
    emailIdentifier: string;
    internalIdentifier: string;
    roleIdentifier: string;
    passwordSecret: string;
    logger: (...args: any[]) => void;
    pending: Map<string, Promise<{
        user: User;
        token: Token;
    }>>;
    constructor(options: JWTAuthMiddelwareOptions);
    deleteAfterExpired(token: any, exp: any): void;
    authAvoidParallel(req: any): Promise<void>;
    private auth;
    private loginUser;
    private getOrCreateUser;
    private updateRoleMapping;
    private ensureRolesExists;
    process(req: any, res: any, next: (err?: Error) => any): void;
}
export {};
