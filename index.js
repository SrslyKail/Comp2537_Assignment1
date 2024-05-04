/* #region setup */

//required additonal files
require("./utils.js");
require("dotenv").config();

//set up imports from node
//express for pathing
const express = require("express");
//express-session for session handling
const session = require("express-session");
//connect-mongo for mongoDB
const MongoStore = require("connect-mongo");
//bcrypt for encryption
const bcrypt = require("bcrypt");
//fs for accessing the file system
const fileSystem = require("fs");

const Joi = require("joi");

const saltRounds = 12;

const port = process.env.PORT || 3000;

//Initialize the app
const app = express();
app.use(express.static(__dirname + "/public"));

//expires after 1 day  (hours * minutes * seconds * millis)
const expireTime = 1 * 60 * 60 * 1000; 

/* #region secrets */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* #endregion secrets */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

/* #endregion setup */

const logoutString = `<form action='/logout' method='get'> <button>Log out</button> </form>`;

app.get("/", (req, res) => {
  let html;
  //If logged in, display members and logout
  if (isLoggedIn(req)) {
    html = `
    Hello, ${getUsername(req)}
    <form action='/members' method='get'>
      <button>Members Page</button>
    </form>
    ${logoutString}`;
  } else {
    // else display links to signup and signin
    html = `
    <form action='/signup' method='get'>
      <button>Sign up!</button>
    </form>
    <form action='/login' method='get'>
      <button>Log in!</button>
    </form>`;
  }
  res.send(html);
});

app.get("/members", (req, res) => {
  let html = `Hello, ${getUsername(req)}`;
  //TODO: Add a random image
  html += logoutString;
  res.send(html);
});

app.get("/signup", (req, res) => {
  let html = fileSystem.readFileSync("./pages/signup.html", "utf8");
  /** @type {qs.ParsedQs} */
  let query = req.query;
  let queryKeys = Object.keys(query);
  if (queryKeys.length != 0){
    if (query.name) {
      html += `<p>${query.name} is already taken</p>`;
    } 
    if (query.maxExceed) {
      html += `<p>name and password cannot exceed 20 characters</p>`;
    }
  }
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;
  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    password: Joi.string().max(20).required(),
  });
  const validationResult = schema.validate({ username, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/signup?maxExceed=1");
    return;
  }
  if (await userCollection.findOne({username: username})) {
    console.log(`${username} is already in use!`);
    res.redirect(`/signup?name=${username}`);
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    username: username,
    password: hashedPassword,
  });
  console.log("Inserted user");

  res.send(fileSystem.readFileSync("./pages/createduser.html", "utf8"));
});

app.get("/login", (req, res) => {
  html = fileSystem.readFileSync("./pages/login.html", "utf8");
  if (req.query.failedLogin) {
    html += "<p>Failed to log in</p>";
  }

  res.send(html);
});

app.post("/loggingin", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login?failedLogin=1");
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("user not found");
    res.redirect("/login?failedLogin=1");
    return;
  }
  if (!await bcrypt.compare(password, result[0].password)) {
    console.log("incorrect password");
    res.redirect("/login?failedLogin=1");
    return;
  }

  console.log("correct password");
  req.session.authenticated = true;
  req.session.username = username;
  req.session.cookie.maxAge = expireTime;

  res.redirect("/loggedIn");
  return;
});

app.get("/loggedin", (req, res) => {
  if (!isLoggedIn(req)) {
    res.redirect("/login");
  }
  res.redirect("/members");
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// app.get('/nosql-injection', async (req,res) => {
// 	var username = req.query.user;

// 	if (!username) {
// 		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
// 		return;
// 	}
// 	console.log("user: "+username);

// 	const schema = Joi.string().max(20).required();
// 	const validationResult = schema.validate(username);

// 	//If we didn't use Joi to validate and check for a valid URL parameter below
// 	// we could run our userCollection.find and it would be possible to attack.
// 	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
// 	// and may result in revealing information about all users or a successful
// 	// login without knowing the correct password.
// 	if (validationResult.error != null) {
// 	   console.log(validationResult.error);
// 	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
// 	   return;
// 	}

// 	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

// 	console.log(result);

//     res.send(`<h1>Hello ${username}</h1>`);
// });

// app.get('/about', (req,res) => {
//   var color = req.query.color;

//   res.send("<h1 style='color:"+color+";'>Patrick Guichon</h1>");
// });

// app.get('/contact', (req,res) => {
//   var missingEmail = req.query.missing;
//   var html = `
//       email address:
//       <form action='/submitEmail' method='post'>
//           <input name='email' type='text' placeholder='email'>
//           <button>Submit</button>
//       </form>
//   `;
//   if (missingEmail) {
//       html += "<br> email is required";
//   }
//   res.send(html);
// });

// app.post('/submitEmail', (req,res) => {
//   var email = req.body.email;
//   if (!email) {
//       res.redirect('/contact?missing=1');
//   }
//   else {
//       res.send("Thanks for subscribing with your email: "+email);
//   }
// });

// app.get('/cat/:id', (req,res) => {

//     var cat = req.params.id;

//     if (cat == 1) {
//         res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
//     }
//     else if (cat == 2) {
//         res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
//     }
//     else {
//         res.send("Invalid cat id: "+cat);
//     }
// });

app.get("*", (req, res) => {
  res.status(404);
  res.send(fileSystem.readFileSync("./pages/404.html", "utf8"));
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
  console.log();
});

/**
 * Checks if the sender of the request is logged in.
 * @param {Request} req
 * @returns {boolean} True if logged in
 */
function isLoggedIn(req) {
  return req.session.authenticated;
}

function getUsername(req){
  return req.session.username;
}
