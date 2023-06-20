const { getAll, create, getOne, remove, update, verifyCode, login, logged, resetPassword, updatePassword } = require('../controllers/user.controlles');
const express = require('express');
const verifyJWT = require('../utils/verifyJWT');

const routerUser = express.Router();

routerUser.route('/') //  /users
    .get(verifyJWT, getAll)  // Ruta protegida
    .post(create);

routerUser.route("/login") //  /users/login
    .post(login)

routerUser.route('/me') //  /users/me
    .get(verifyJWT, logged)    // Ruta protegida

routerUser.route("/reset_password") // /users/reset_password
    .post(resetPassword)

routerUser.route('/:id') //  /users/:id
    .get(verifyJWT, getOne)    // Ruta protegida
    .delete(verifyJWT, remove)    // Ruta protegida
    .put(verifyJWT, update);    // Ruta protegida

routerUser.route("/verify/:code") //  /users/verify/:code
    .get(verifyCode)


routerUser.route("/reset_password/:code") //  /users/reset_password/:code
    .post(updatePassword)



module.exports = routerUser;

