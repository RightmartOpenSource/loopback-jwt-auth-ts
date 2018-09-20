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

export function uuid(): string{
     //http://stackoverflow.com/questions/105034/how-to-create-a-guid-uuid-in-javascript
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

}