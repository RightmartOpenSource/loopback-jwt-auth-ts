"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class UnauthorizedError extends Error {
    constructor() {
        super(...arguments);
        this.status = 401;
    }
}
exports.default = UnauthorizedError;
//# sourceMappingURL=UnauthorizedError.js.map