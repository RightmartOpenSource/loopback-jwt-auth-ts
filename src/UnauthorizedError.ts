export default class UnauthorizedError extends Error {
    private status: number = 401;
}