const express = require("express");
const passportService = require("../services/passport");
const passport = require("passport");
const router = express.Router();

const requireAuth = passport.authenticate("jwt", { session: false });
const requireLogin = passport.authenticate("local", { session: false });

const employee_authentication_controller = require("../controllers/employee-authentication.controller");

module.exports = app => {
  app.get("/", requireAuth, (req, res) => {
    res.send({ hi: "there" });
  });
  app.get("/test", employee_authentication_controller.test);
  app.post("/login", requireLogin, employee_authentication_controller.login);
  app.post("/register", employee_authentication_controller.register);
  app.post("/forgot", employee_authentication_controller.forgot);
  app.post("/reset/:token", employee_authentication_controller.reset);
};
