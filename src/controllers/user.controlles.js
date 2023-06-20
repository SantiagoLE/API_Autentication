const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require("bcrypt");
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require("jsonwebtoken")


// Obtener todos los resultados (usuarios)
const getAll = catchError(async (req, res) => {
    const results = await User.findAll(); // Se aplica metodo zequelize findAll() para traer todos los resultados
    return res.json(results); // Se retornan todos los resultados en un .json
});


// Crear un nuevo registro de usuario 
const create = catchError(async (req, res) => {

    const { email, password, firstName, lastName, country, image, frontBaseUrl } = req.body // Se desestructura el body para tener control del mismo, frontBaseUrl lo pasa la gente del front
    const hashPassword = await bcrypt.hash(password, 10)  // Con el uso de bcrypt y el medoto .hash , se encrypta el password que viene del body 

    const body = { email, firstName, lastName, country, image, password: hashPassword } // Se Asignan las variables desesctructuradas y la columna password referenciada con hashPassword que es el password ya encryptado
   
    const result = await User.create(body); // Se aplica metodo zequelize .create y se le pasa el body con el password encryptado, para crear un nuevo registro (usuario)

    const code = require('crypto').randomBytes(64).toString('hex') // Se genera un codigo random mediante la sintaxis 
    const url = `${frontBaseUrl}/verify_email/${code}` // Se genera la url con frontBaseUrl que es dinamico viene del body, verify_email que es estatico y code que es el codigo random generado en la linea anterior

    // Envio de email (Datos de email y password de email en .env)
    await sendEmail({
        to: email,  // email que viene del body, ingresado por el usuario
        subject: "Verificacion de cuenta",   // Asunto del email
        // Diseño html del email a enviar
        html: `    
        <h2>Haz click en el siguiuente enlace para verificar la cuenta:</h2>
        <a href=${url}>Click me!</a>
        `
    })

    const bodyCode = { code, userId: result.id } // Se crea un body desestructurado con los campos code que hace referencia a la columna code del modelo EmailCode.js y el valor de la const code, lineas antes creado. Tambien el campo userId creado por sequelize mediante la relacion del index.js de model, este campo userId se referencia con el valor de result en la propiedad id (result.id)
    await EmailCode.create(bodyCode)  // Se aplica metodo zequelize .create y se le pasa el body con los campos desestructurados, para crear un nuevo registro de codigo code y  userId referenciado al registro user en la propiedad id (user.id)


    return res.status(201).json(result); // Se retorna el resultado (Usuario) creado
});


// Obtener un resultado (usuario) mediante el Id
const getOne = catchError(async (req, res) => {
    const { id } = req.params;  // Se desestructura el id que viene por parametros
    const result = await User.findByPk(id);  // Se aplica metodo zequelize .findByPk y se le pasa el id para traer el resultado (usuario) especifico
    if (!result) return res.sendStatus(404); // Condicion si el resultado (usuario) buscado no existe, retorna el codigo 404
    return res.json(result); // Si el resultado (usuario) buscado con el id existe, retorna el resultado (usuario)
});


// Eliminar un resultado (usuario) mediante el Id
const remove = catchError(async (req, res) => {
    const { id } = req.params; // Se desestructura el id que viene por parametros
    const remove = await User.destroy({ where: { id } }); // Se aplica metodo zequelize .destroy y se le indica de donde con el {where: } y el {id} para eliminar el resultado (usuario) especifico
    if (!remove) return res.sendStatus(404) // Condicion si el resultado (usuario) buscado no existe, retorna el codigo 404
    return res.sendStatus(204); // Si el resultado (usuario) es eliminado correctamente, retorna el codigo 204
});


// Actualizar un resultado (usuario) mediante el Id
const update = catchError(async (req, res) => {
    const { id } = req.params; // Se desestructura el id que viene por parametros
    const result = await User.update(req.body, { where: { id }, returning: true }); // Se aplica metodo zequelize .update, se le pasa el body directamente del req.body, se le indica de donde con el {where: } y el {id} y el returning: true para retornar el resultado (usuario) ya actualizado
    if (result[0] == 0) return res.sendStatus(404); // Condicion si el array resultante, en la posicion 0 es igual a 0 , retorna el codigo 404
    return res.json(result[1][0]);  // Si el array resultante, en la posicion 0 es igual a 1 , retorna el resultado (usuario) en la posicion [1][0]
});


// Verificar el codigo 
const verifyCode = catchError(async (req, res) => {

    const { code } = req.params  // Se desestructura el codigo que viene por parametros

    const codeUser = await EmailCode.findOne({ where: { code } }) // Se aplica metodo zequelize .findOne y se le pasa el {where:{ code }} para que busque el registro completo en EmailCode que tenga el code que se esta buscando
    if (!codeUser) return res.sendStatus(401) // Condicion si el codigo buscado no existe, retorna el codigo 401

    const body = { isVerified: true } // Si encuentra el codigo, asigna true a isVerified, con esto se marca la cuenta verificada
    const userUpdate = await User.update(body, { where: { id: codeUser.userId }, returning: true } // Se aplica metodo zequelize .update, se le pasa el body que en este caso seria la columna isVerified con el valor true, se le indica de donde con el {where: } y el {id} que en este caso esta referenciado con el registro completo de codeUser en la propiedad userId... y el returning: true para retornar el resultado (usuario) ya actualizado
    )

    await codeUser.destroy() // Se elimina el registro codeUser despues de ser verificado
    return res.json(userUpdate[1][0]) // Se retorna el registro (usuario) actualizado
})


// Hacer login
const login = catchError(async (req, res) => {

    const { email, password } = req.body; // Se desestructura el body 

    // verificacion email
    const user = await User.findOne({ where: { email } }); // Se aplica metodo zequelize .findOne y se le pasa el {where:{ email }} para que busque el registro completo en User que tenga el email que se esta buscando
    if (!user) return res.sendStatus(401); // Condicion si el registro con ese email buscado no existe, retorna el codigo 401

    // verificacion password
    const isValidPassword = await bcrypt.compare(password, user.password); // Con el uso de bcrypt y el medoto .compare , Se compara el password que viene del body y el password encrytado en user propiedad password (user.password)
    if (!isValidPassword) return res.sendStatus(401); // Condicion si la comparacion es false, retorna el codigo 401
    if (!user.isVerified) return res.sendStatus(401); // Condicion si el user en la propiedad isVerified es false, retorna el codigo 401

    // Creacion del token del usuario
    const token = jwt.sign(
        { user },
        process.env.TOKEN_SECRET,
        { expiresIn: '1d' }
    )

    return res.json({ user, token }); // Se retorna el usuario con el token de ese usuario
})


// Mostrar informacion del usuario logeado
const logged = catchError(async (req, res) => {

    const user = req.user // Traemos la informacion del usuario logeado
    return res.json(user) // Se retorna el usuario logeado
})


// Solicitud cambio de password
const resetPassword = catchError(async (req, res) => {

    const { email, frontBaseUrl } = req.body; // Se desestructura el body 
    const user = await User.findOne({ where: { email } }); // Se aplica metodo zequelize .findOne y se le pasa el {where:{ email }} para que busque el registro completo en User que tenga el email que se esta buscando
    if (!user) return res.sendStatus(401); // Condicion si el registro con ese email buscado no existe, retorna el codigo 401

    const code = require('crypto').randomBytes(64).toString('hex') // Se genera un codigo random mediante la sintaxis 
    const url = `${frontBaseUrl}/reset_password/${code}` // Se genera la url con frontBaseUrl que es dinamico viene del body, reset_password que es estatico y code que es el codigo random generado en la linea anterior

        // Envio de email (Datos de email y password de email en .env)
    await sendEmail({
        to: email, // email que viene del body, ingresado por el usuario
        subject: "Soicitud cambio de contraseña", // Asunto del email
        // Diseño html del email a enviar
        html: ` 
        <h2>Haz click en el siguiuente enlace para cambiar la contraseña:</h2>
        <a href=${url}>Click me!</a>
        `
    })

    const body = { code, userId: user.id } // Se crea un body desestructurado con los campos code que hace referencia a la columna code del modelo EmailCode.js y el valor de la const code, lineas antes creado. Tambien el campo userId creado por sequelize mediante la relacion del index.js de model, este campo userId se referencia con el valor de result en la propiedad id (result.id)
    await EmailCode.create(body) // Se aplica metodo zequelize .create y se le pasa el body con los campos desestructurados, para crear un nuevo registro de codigo code y  userId referenciado al registro user en la propiedad id (user.id)

    return res.json(user)  // Se retorna el usuario que solicita el cambio de contraseña
})

// Actualizacion de password 
const updatePassword = catchError(async (req, res) => {
    //  /reset_password/:code
    const { code } = req.params // Se desestructura el code que viene de los parametros
    const { password } = req.body // Se desestructura el password que viene del body

    const userCode = await EmailCode.findOne({ where: { code } }) // Se aplica metodo zequelize .findOne y se le pasa el {where:{code}} para que busque el registro completo en EmailCode que tenga el code que se esta buscando
    if (!userCode) return res.sendStatus(401) // Condicion si el codigo buscado no existe, retorna el codigo 401

    const hashPassword = await bcrypt.hash(password, 10) // Con el uso de bcrypt y el medoto .hash , se encrypta el password que viene del body 
    const body = { password: hashPassword } // Se referencia la columna password con hashPassword que es el password ya encryptado

    const user = await User.update(body, { where: { id: userCode.userId } }) // Se aplica metodo zequelize .update, se le pasa el body que en este caso seria la columna password con el password encryptado, se le indica de donde con el {where: } y el {id} que en este caso esta referenciado con el registro completo de userCode en la propiedad userId... y el returning: true para retornar el resultado (usuario) ya actualizado

    if (user[0] === 0) return res.sendStatus(404); // Condicion si el array resultante, en la posicion 0 es igual a 0 , retorna el codigo 404
    await userCode.destroy() // Se elimina el registro userCode despues de ser actualizado el password 
    return res.json(user[0]) // Se retorna la posicion 0 del array resultante como respuesta
})




module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyCode,
    login,
    logged,
    resetPassword,
    updatePassword,

}