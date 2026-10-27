const express = require("express");
const crypt = require("crypto");
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const mysql = require("mysql2");

const conn = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: process.env.ROOTPASS,
  database: "user_assignment",
  port: 3306,
});

const hashRounds = 100;
const hashLength = 64;

conn.connect(function (err) {
  if (err) {
    console.log("Could not connect to MySQL", err);
    return;
  }

  console.log("Database connection established");
});

// Reusable MovieShelf response page
function sendPage(res, title, heading, message, linkText, linkHref) {
  res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MovieShelf | ${title}</title>
            <link rel="stylesheet" href="/style.css">
        </head>
        <body>
            <main class="page">
                <header class="brand">
                    <h1 class="brand-name">Movie<span>Shelf</span></h1>
                    <p class="tagline">Your next favorite story starts here.</p>
                </header>

                <section class="card">
                    <h2>${heading}</h2>
                    <p class="description">${message}</p>
                    <p class="back-link">
                        <a href="${linkHref}">${linkText}</a>
                    </p>
                </section>
            </main>
        </body>
        </html>
    `);
}

// Registration
app.post("/register", function (req, res) {
  const username = req.body.username;
  const email = req.body.email;
  const plainPass = req.body.password;

  const salt = crypt.randomBytes(16).toString("hex");

  const hashedPass = crypt
    .pbkdf2Sync(plainPass, salt, hashRounds, hashLength, "sha512")
    .toString("hex");

  const sql = `
        INSERT INTO accounts (username, email, password_hash, salt)
        VALUES (?, ?, ?, ?)
    `;

  conn.query(sql, [username, email, hashedPass, salt], function (err) {
    if (err) {
      if (err.code === "ER_DUP_ENTRY") {
        return sendPage(
          res,
          "Registration",
          "Account already exists",
          "That username or email is already registered.",
          "Try registering again",
          "/register.html",
        );
      }

      console.log("Registration error:", err);

      return sendPage(
        res,
        "Registration",
        "Registration failed",
        "We could not complete your registration. Please try again.",
        "Back to Registration",
        "/register.html",
      );
    }

    sendPage(
      res,
      "Registered",
      "You're on the list!",
      "You have successfully registered",
      "Go to Login",
      "/login.html",
    );
  });
});

// Login
app.post("/login", function (req, res) {
  const username = req.body.username;
  const plainPass = req.body.password;

  const sql = "SELECT * FROM accounts WHERE username = ?";

  conn.query(sql, [username], function (err, results) {
    if (err) {
      console.log("Login error:", err);

      return sendPage(
        res,
        "Login",
        "Login failed",
        "We could not process your login. Please try again.",
        "Go back to Login",
        "/login.html",
      );
    }

    if (results.length === 0) {
      return sendPage(
        res,
        "Login",
        "Login unsuccessful",
        "The login credentials were incorrect",
        "Go back to Login",
        "/login.html",
      );
    }

    const user = results[0];

    const hashedPass = crypt
      .pbkdf2Sync(plainPass, user.salt, hashRounds, hashLength, "sha512")
      .toString("hex");

    if (hashedPass !== user.password_hash) {
      return sendPage(
        res,
        "Login",
        "Login unsuccessful",
        "The login credentials were incorrect",
        "Go back to Login",
        "/login.html",
      );
    }

    sendPage(
      res,
      "Welcome",
      "Welcome to MovieShelf!",
      "You have logged in successfully",
      "Back to Login",
      "/login.html",
    );
  });
});

app.listen(3000, function () {
  console.log("Server running at http://localhost:3000");
});
