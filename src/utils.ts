export async function saveUpsertWithWhere(model: any, where: any , data: any , options?: any) {

    if (where.where) {
        throw new Error("where.where as argument is not allowed");
    }

    try {
        return await model.upsertWithWhere(where, data, options);
    } catch (e) {
        const dbEntry = await model.findOne({where});

        if (dbEntry === null) {
            throw e;
        }
        return dbEntry.updateAttributes(data, options);
    }
}