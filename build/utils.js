"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
async function saveUpsertWithWhere(model, where, data, options) {
    if (where.where) {
        throw new Error("where.where as argument is not allowed");
    }
    try {
        return await model.upsertWithWhere(where, data, options);
    }
    catch (e) {
        const dbEntry = await model.findOne({ where });
        if (dbEntry === null) {
            throw e;
        }
        return dbEntry.updateAttributes(data, options);
    }
}
exports.saveUpsertWithWhere = saveUpsertWithWhere;
//# sourceMappingURL=utils.js.map