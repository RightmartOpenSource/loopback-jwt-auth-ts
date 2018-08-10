export default class UnauthorizedError extends Error {
    private status: number = 401;
    private code: string = "credentials_required";
}