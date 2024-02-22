import express from "express";
import cors from "cors";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3001;
const saltRounds = 10;
env.config();

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: {
            maxAge: 10 * 365 * 24 * 60 * 60
        }
    })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});
db.connect();

app.get('/api/message', (req, res) => {
    res.json({ message: 'Hello World!' });
});

app.get('/api/status', (req, res) => {
    res.json({ isAuthenticated: req.isAuthenticated() });
});

app.get("/api/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "Errore durante il logout." });
        }
        res.status(200).json({ success: true, message: "Logout effettuato con successo." });

    });
});

app.post("/api/register", async (req, res) => {
    const { email, password, username, firstname, lastname } = req.body;
    
    try {
        const findUser = await db.query("SELECT * FROM users WHERE email = $1", [
            email,
        ]);
    
        if (findUser.rows.length > 0) {
            return res.status(409).json({ message: "L'email inserita é giá in uso." }); 
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.error("Error hashing password:", err);
                } else {
                    const result = await db.query(
                    "INSERT INTO users (email, password, username, firstname, lastname) VALUES ($1, $2, $3, $4, $5) RETURNING *",
                    [email, hash, username, firstname, lastname]
                    );
                    const user = result.rows[0];
                    req.login(user, (err) => {
                        if (err) {
                            console.error("Login error:", err);
                            return res.status(500).json({ success: false, message: "Errore durante il login." });
                        }
                        res.status(201).json({ user: { id: user.id, email: user.email, username: user.username, firstname: user.firstname, lastname: user.lastname } });
                    });
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});

passport.serializeUser((user, cb) => {
    cb(null, user.id);
});

passport.deserializeUser((id, cb) => {
    db.query('SELECT * FROM users WHERE id = $1', [id], (err, result) => {
        if (err) {
            return cb(err);
        }
        cb(null, result.rows[0]);
    });
});


app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});