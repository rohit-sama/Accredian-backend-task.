const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");

const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");

const bcrypt = require('bcrypt');
const saltRound = 10;

const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());
app.use(
    cors({
        origin: ["http://localhost:5173"],
        methods: ["GET", "POST"],
        credentials: true,
    })
);
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
    session({
        key: "userId",
        secret: "mynameisrohit",
        resave: false,
        saveUninitialized: false,
        cookie: {
            expires: 60 * 60 * 24,
            httpOnly: true, // Add this line
        },
    })
);


const db = mysql.createConnection({
    user: "root",
    host: "localhost",
    password: "therohit",
    database: "authsql", 
});

app.post('/register', (req, res)=> {
    const username = req.body.username;
    const password = req.body.password; 

    bcrypt.hash(password,saltRound, (err, hash) => {

        if (err) {
            console.log(err)
        }
        db.execute( 
            "INSERT INTO users (username, password) VALUES (?,?)",
            [username, hash], 
            (err, result)=> {
                console.log(err);
            }
        );
    })
});

const verifyJWT = (req, res, next) => {
   
};

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            res.status(500).json({ message: "Error logging out" });
        } else {
            res.clearCookie('userId'); // Clear the session cookie
            res.status(200).json({ message: "Successfully logged out" });
        }
    });
});


app.get('/isUserAuth', (req, res) => {
    const token = req.headers["x-access-token"];

    if (!token) {
        res.status(401).json({ message: "Authentication token missing" });
    } else {
        jwt.verify(token, "jwtSecret", (err, decoded) => {
            if (err) {
                console.log(err);
                res.status(403).json({ auth: false, message: "Failed to authenticate" });
            } else {
                // Authentication successful
                req.userId = decoded.id;
                res.status(200).json( {message: "You are authenticated Congrats:", auth: true});
            }
        });
    }
});


app.get("/login", (req, res) => {
    if (req.session.user) {
      res.send({ loggedIn: true, user: req.session.user });
    } else {
      res.send({ loggedIn: false });
    }
});

app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password; 
    console.log(username, password)

    db.execute(
        "SELECT * FROM users WHERE username = ?;",
        [username], 
        (err, result)=> {
            if (err) {
                res.send({err: err});
            } 

            if (result.length > 0) {
                bcrypt.compare(password, result[0].password, (error, response) => {
                    if (response) {
                        const id = result[0].id
                        const token = jwt.sign({id}, "jwtSecret", {
                            expiresIn: 300,
                        })
                        req.session.user = result;

                        console.log(req.session.user);
                        res.json({auth: true, token: token, result: result});
                    } else{
                        res.json({auth: false, message: "Wrong username password"}); 
                    }
                })
            } else {
                res.json({auth: false, message: "no user exists"});
            }
        }
    );
});

app.listen(3000, () => {
    console.log("running server");
});