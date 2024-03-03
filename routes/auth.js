const express = require("express");
const router = new express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const ExpressError = require("../expressError");
const db = require("../db");
const User = require("../models/user");
const { SECRET_KEY } = require("../config");


/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async function(req, res, next) {
    try {
        const { username, password } = req.body;
        const login = await User.authenticate(username, password);
        if (login) {
            let token = jwt.sign({username}, SECRET_KEY);
            await User.updateLoginTimestamp(username);
            return res.json({token});
        }
    }

    catch(err) {
        return next(err);
    }
})


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async function(req, res, next) {
    try {
        let result = await User.register(req.body);
        let token = jwt.sign({username}, SECRET_KEY);
        await User.updateLoginTimestamp(result.username);
        return res.json({token});
    }

    catch(err) {
        return next(err);
    }
})

module.exports = router;