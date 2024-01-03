const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const env = require('dotenv').config()
const session = require("express-session");
const passport = require("passport");
const mysql = require("mysql");
const LocalStrategy = require("passport-local").Strategy;
const crypto = require("crypto");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const randomToken = require("random-token");
const util = require('util');
const quotes = require("./quotes.json");
const MySQLStore = require('express-mysql-session')(session);
const TelegramBot = require('node-telegram-bot-api');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const otpGenerator = require('otp-generator');
const otp = otpGenerator.generate(6, { upperCaseAlphabets: false, lowerCaseAlphabets: false, specialChars: false });
const fotp = otp;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

// const sessionSecret = crypto.randomBytes(64).toString('hex');

app.use(session({
    secret: "sessionSecret",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const connection = mysql.createConnection({
    host: process.env.SQL_HOST,
    port: process.env.SQL_PORT,
    user: process.env.SQL_USER,
    password: process.env.SQL_PASSWORD,
    database: process.env.SQL_DATABASE,
    multipleStatements: true
});

connection.connect((err) => {
    if (err) {
        console.error("Database connection failed:", err);
    } else {
        console.log("Successfully connected to Database");
    }
});

const verifyCallback = async (username, password, done) => {
    try {
        const results = await queryAsync('SELECT * FROM users WHERE username = ?', [username]);

        if (results.length === 0) {
            return done(null, false);
        }

        const isValid = validPassword(password, results[0].hash, results[0].salt);
        const user = {
            id: results[0].id,
            username: results[0].username,
            name: results[0].name,
            apiKey: results[0].apiKey,
            profilePic: results[0].profilePic,
            avatar: results[0].avatar,
            discordId: results[0].discordId
        };

        return isValid ? done(null, user) : done(null, false);
    } catch (error) {
        return done(error);
    }
};

const strategy = new LocalStrategy(verifyCallback);
passport.use(strategy);

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        cb(null, {
            id: user.id,
            username: user.username,
            name: user.name,
            apiKey: user.apiKey,
            profilePic: user.profilePic,
            avatar: user.avatar,
            discordId: user.discordId
        });
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function(req, accessToken, refreshToken, profile, done) {
        //console.log(profile)
        connection.query("SELECT * FROM users WHERE googleId = ?", [profile.id], (err, users) => {
            if (err) {
                return done(err);
            }
            if (users.length !== 0) {
                const us = {
                    name: users[0].name,
                    profilePic: users[0].profilePic,
                    apiKey: users[0].apiKey,
                    username: users[0].username
                }
                return done(null, us)
            }
            if (users.length === 0) {
                let newUser = {
                    googleId: profile.id,
                    name: profile.displayName,
                    profilePic: profile.photos[0].value,
                    username: profile.emails[0].value
                };
                connection.query("INSERT INTO users (googleId, name, profilePic, username, verified) VALUES (?, ?, ?, ?, ?)",
                    [newUser.googleId, newUser.name, newUser.profilePic, newUser.username, 1], (err, rows) => {
                        if (err) {
                            console.log(err);
                        }

                        return done(null, newUser);
                    })
            }
        });
    }
));

passport.use(new DiscordStrategy({
        clientID: process.env.DISCORD_CLIENT_ID,
        clientSecret: process.env.DISCORD_CLIENT_SECRET,
        callbackURL: process.env.DISCORD_CALLBACK_URL
    },
    function(req, accessToken, refreshToken, identify, done) {
        //console.log(identify)
        connection.query("SELECT * FROM users WHERE discordId = ?", [identify.id], (err, users) => {
            if (err) {
                return done(err);
            }
            if (users.length !== 0) {
                const us = {
                    name: users[0].name,
                    avatar: users[0].avatar,
                    discordId: users[0].discordId,
                    apiKey: users[0].apiKey,
                    username: users[0].username
                }
                return done(null, us)
            }
            if (users.length === 0) {
                let newUser = {
                    discordId: identify.id,
                    name: identify.global_name,
                    avatar: identify.avatar,
                    username: identify.username
                };
                connection.query("INSERT INTO users (discordId, name, avatar, username, verified) VALUES (?, ?, ?, ?, ?)",
                    [newUser.discordId, newUser.name, newUser.avatar, newUser.username, 1], (err, rows) => {
                        if (err) {
                            console.log(err);
                        }

                        return done(null, newUser);
                    })
            }
        });
    }
));

app.get("/", async function(req, res) {
    if (req.isAuthenticated()) {
        const user = await queryAsync("SELECT * FROM users WHERE username = ?", [req.body.username || req.user.username]);
        res.render("home", {
            auth: req.isAuthenticated(),
            profilePic: user[0].profilePic,
            avatar: user[0].avatar,
            discordId: user[0].discordId,
            name: user[0].name,
            username: user[0].username
        });
    } else {
        res.render("home", {
            auth: req.isAuthenticated()
        });
    }
});

app.get("/auth/google", passport.authenticate("google", {
    scope: ["profile", "email"]
}));

app.get("/auth/google/profile", passport.authenticate("google", {
        failureRedirect: "/login"
    }),
    function(req, res) {
        res.redirect("/profile");
    }
)

app.get("/auth/discord", passport.authenticate("discord", {
    scope: ["identify"]
}));

app.get("/auth/discord/profile", passport.authenticate("discord", {
        failureRedirect: "/login"
    }),
    function(req, res) {
        res.redirect("/profile")
    }
)

app.get("/login", function(req, res) {
    if (req.isAuthenticated()) {
        res.redirect("/profile");
    } else {
        res.render("login");
    }
});

app.get("/register", function(req, res) {
    if (req.isAuthenticated()) {
        res.redirect("/profile");
    } else {
        res.render("register");
    }
});

app.get("/logout", function(req, res, next) {
    req.logout(function(err) {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});

app.get("/profile", async function(req, res) {
    if (req.isAuthenticated()) {
        const user = await queryAsync("SELECT * FROM users WHERE username = ?", [req.body.username || req.user.username]);
        if(user[0].verified == 1){
        res.render("profile", {
            apiKey: user[0].apiKey,
            name: user[0].name,
            profilePic: user[0].profilePic,
            avatar: user[0].avatar,
            discordId: user[0].discordId
        })}else{
          const username = user[0].username
          sendOtp(username);
          res.render("verify", {
            error: `We have sent you an verification code on ${username}`,
            username: username
          })
        }
    } else {
        res.redirect("/login");
    }
});

/*middleware*/
async function isValidApiKey(apiKey) {
    try {
        const user = await queryAsync("SELECT * FROM users WHERE apiKey = ?", [apiKey]);
        return !!user[0];
    } catch (error) {
        console.error("Error checking API key:", error);
        return false;
    }
}

function validPassword(password, hash, salt) {
    var hashVerify = crypto.pbkdf2Sync(password, salt, 10000, 60, 'sha512').toString('hex');
    return hash === hashVerify;
}

function genPassword(password) {
    var salt = crypto.randomBytes(32).toString('hex');
    var genhash = crypto.pbkdf2Sync(password, salt, 10000, 60, 'sha512').toString('hex');
    return {
        salt: salt,
        hash: genhash
    };
}

const queryAsync = util.promisify(connection.query).bind(connection);

app.post("/register", async function(req, res) {
    try {
        const username = req.body.username;
        const existingUsers = await queryAsync("SELECT * FROM users WHERE username = ?", [req.body.username]);

        if (existingUsers.length !== 0) {
            return res.render("register", {
                error: "An account with this email already exists. Please login."
            });
        }

        const saltHash = genPassword(req.body.password);
        const salt = saltHash.salt;
        const hash = saltHash.hash;
        //const apiKey = randomToken(26);

        await queryAsync("INSERT INTO users (username, name, hash, salt) VALUES (?, ?, ?, ?)",
            [req.body.username, req.body.name, hash, salt]);
        
      
        sendOtp(username);
        return res.render("verify", {
            error: `We have sent you an otp on ${username}`,
            username: req.body.username
        });
    } catch (error) {
        console.log(error);
        return res.render("register", {
            error: "Registration failed. Please try again."
        });
    }
});

app.post("/login", function(req, res) {
    connection.query("SELECT * FROM users WHERE username = ?", [req.body.username], async (err, users) => {
        try {
            if (err) {
                return res.render("login", {
                    error: "An unexpected error occurred."
                });
            }

            if (!users || users.length === 0) {
                return res.render("login", {
                    error: "Invalid username or password."
                });
            }
          
            if (users[0].salt === null) {
                return res.render("login", {
                    error: "This is already exist with google. Please login with google."
                });
            }

            const user = {
                name: users[0].name,
                username: users[0].username,
                apiKey: users[0].apiKey
            };

            const info = await new Promise((resolve, reject) => {
                passport.authenticate("local", function(err, info) {
                    if (err) {
                        return reject(err);
                    }
                    resolve(info);
                })(req, res);
            });

            if (!info || info.message === "Missing credentials") {
                return res.render("login", {
                    error: "Invalid username or password."
                });
            }

            req.login(user, function(err) {
                if (err) {
                    console.log(err);
                    return res.render("login", {
                        error: "An unexpected error occurred."
                    });
                }
                return res.redirect("/profile");
            });
        } catch (error) {
            console.log(error);
            return res.render("login", {
                error: "An unexpected error occurred."
            });
        }
    });
});

app.post("/generate-api-key", async function(req, res) {
    try {
        if (req.isAuthenticated()) {
            const username = req.user.username;
            const updateUserQuery = "UPDATE users SET apiKey = ? WHERE username = ?";
            const newApiKey = randomToken(26);

            await queryAsync(updateUserQuery, [newApiKey, username]);

            res.redirect("/profile");
        } else {
            res.redirect("/login");
        }
    } catch (error) {
        console.error("Error generating API key:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/contact", function(req, res) {
    res.render("contact");
});

app.post("/contact", function(req, res) {
    const token = process.env.TELEGRAM_TOKEN;
    const bot = new TelegramBot(token);
    const name = req.body.name;
    const email = req.body.email;
    const problem = req.body.problem;
    bot.sendMessage(process.env.TELEGRAM_CHAT_ID, `Name: ${name}\n\nEmail: ${email}\n\nProblem: ${problem}`)
        .then(() => {
            res.render("contact", {
                error: 'Problem sent.'
            });
        })
        .catch((error) => {
            console.error(error);
            res.status(500).render("contact", {
                error: 'Error sending message'
            });
        });
});

app.get("/forgot-password", function(req, res) {
    res.render("forgot-password");
})

app.post('/forgot-password', async (req, res) => {
    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.MY_EMAIL,
                pass: process.env.MY_PASSWORD,
            },
        });

        const token = jwt.sign({
                data: process.env.TOKEN_DATA,
            },
            process.env.JWT_VERIFICATION_SECRET, {
                expiresIn: '10m'
            }
        );

        const mailConfigurations = {
            from: process.env.MY_EMAIL,
            to: req.body.email,
            subject: 'Email Verification',
            text: `Hi! There, You have recently requested to reset your password.\nPlease follow the given link to reset your password https://quotesapi25.glitch.me/verify/${token}/${req.body.email}\nThanks`,
        };

        const info = await transporter.sendMail(mailConfigurations);

        console.log('Email Sent Successfully');
        //console.log(info);

        res.render('forgot-password', {
            error: `We have sent you an email on ${req.body.email}`,
        });
    } catch (error) {
        console.error(error);
        res.status(500).render('forgot-password', {
            error: 'Email does not exist or there was an issue sending the email.',
        });
    }
});

app.get('/verify/:token/:username', (req, res) => {
    const { token } = req.params;
    const { username } = req.params;
    jwt.verify(token, process.env.JWT_VERIFICATION_SECRET, function(err, decoded) {
        if (err) {
            console.log(err);
            res.send("Email verification failed, possibly the link is invalid or expired");
        } else {
            console.log("Email verified successfully.");
            res.render("reset-password", {
              username: username
            });
        }
    });
});

app.post("/reset-password", async function(req, res) {
    const username = req.body.email;
    const saltHash = genPassword(req.body.password);
    const salt = saltHash.salt;
    const hash = saltHash.hash;

    await queryAsync("UPDATE users SET salt = ?, hash = ? WHERE username = ?",
        [salt, hash, username]);

    return res.render("login", {
        error: "Your password is changed. Please Login"
    });
})

async function sendOtp(username){
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.MY_EMAIL,
                pass: process.env.MY_PASSWORD,
            },
        });
        
        const mailConfigurations = {
            from: process.env.MY_EMAIL,
            to: username,
            subject: 'Email Verification',
            text: `Hi! There, your verification code is ${otp}`,
        };

        const info = await transporter.sendMail(mailConfigurations);

        console.log('Email Sent Successfully');
        //console.log(info);
}

app.post("/otp", async function(req, res){
  if(req.body.otp == fotp){
    await queryAsync("UPDATE users SET verified = ? WHERE username = ?",
        [1, req.body.username]);
    res.render("login", {
        error: "Verification succeeded. Please login"
    });
  }else{
    res.render("verify", {
        error: "Invalid OTP"
    })
  }
});

app.post("/delete", async function (req, res) {
  try {
    const username = req.user.username;
    await queryAsync("DELETE FROM users WHERE username = ?", [username]);
    res.redirect("/logout");
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.use("/quote", async function(req, res, next) {
    const apiKey = req.query.apiKey || req.headers['x-api-key'] || req.body.apiKey;

    if (await isValidApiKey(apiKey)) {
        next();
    } else {
        res.status(401).json({
            error: "Invalid API Key"
        });
    }
});

app.get("/quote/random", (req, res) => {
    let x = Math.floor((Math.random() * 5420) + 0);
    const random_quote = quotes[x];
    res.json(random_quote);
});

app.get("/quote/:quoteAuthor", (req, res) => {
    const authorName = req.params.quoteAuthor;
    const authorQuotes = quotes.filter((quote) => quote.quoteAuthor === authorName);

    if (authorQuotes.length === 0) {
        return res.status(404).json({
            message: "Quotes not found for the specified author"
        });
    }

    const index = Math.floor(Math.random() * authorQuotes.length);
    const randomQuote = authorQuotes[index];

    res.json(randomQuote);
});

app.use(function(req, res, next) {
    res.status(404).render("404");
});

app.listen(3000, function() {
    console.log("server is running on port 3000");
});