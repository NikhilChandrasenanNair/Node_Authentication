const express = require("express");
const http = require("http");
const bodyParser = require("body-parser");
const morgan = require("morgan");
const secret = require("./config/employee.config");

// Import routes from employee
const router = require("./routes/employee.route");

// Initializing express app
const app = express();

const server = http.createServer(app);

// Set up mongoose connection
const mongoose = require("mongoose");

mongoose.connect(
  secret.database,
  { useNewUrlParser: true }
);
mongoose.Promise = global.Promise;
mongoose.set("useFindAndModify", false);
mongoose.set("useCreateIndex", true);
let db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error: "));

// App setup
app.use(morgan("combined"));

// Parse the incoming request bodies
app.use(bodyParser.json({ type: "*/*" }));
app.use(bodyParser.urlencoded({ extended: false }));

//app.use("/employee", employeeSetup);
router(app);

server.listen(secret.port, () => {
  console.log("Server is up and running on port number ", secret.port);
});
