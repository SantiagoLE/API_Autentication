const EmailCode = require("./EmailCode");
const User = require("./User");


// Relacion UNO a UNO
EmailCode.belongsTo(User) //userId (llave foranea)
User.hasOne(EmailCode)