import express from "express";
import cors from "cors";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import { body, validationResult } from 'express-validator';

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

app.get('/api/status', (req, res) => {
    if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "Errore interno del server durante il login. Riprova piú tardi." });
    }
    res.json({ isAuthenticated: req.isAuthenticated() });
});

app.get("/api/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "Errore interno del server durante il logout. Riprova piú tardi." });
        }
        res.status(200).json({ success: true, message: "Logout effettuato con successo." });

    });
});

app.post("/api/register", [
    body('email')
        .trim()
        .isEmail().withMessage('Inserisci un indirizzo email valido.')
        .isLength({ max: 255 }).withMessage('L\'indirizzo email non puó contenere piú di 255 caratteri.'),

    body('password')
        .isLength({ min: 8 }).withMessage('La password deve contenere almeno 8 caratteri.')
        .matches(/\d/).withMessage('La password deve contenere almeno un numero.')
        .matches(/[a-z]/).withMessage('La password deve contenere almeno una lettera minuscola.')
        .matches(/[A-Z]/).withMessage('La password deve contenere almeno una lettera maiuscola.')
        .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('La password deve contenere almeno un simbolo speciale.'),

    body('username')
        .trim()
        .isLength({ min: 3, max: 30 }).withMessage('L\'username deve contenere tra 3 e 30 caratteri.')
        .matches(/^[a-zA-Z0-9_]+$/).withMessage('L\'username può contenere solo lettere, numeri e underscore.'),

    body('firstname')
        .trim()
        .isLength({ max: 50 }).withMessage('Il nome non puó contenere piú di 50 caratteri.')
        .matches(/^[a-zA-Z]+(?: [a-zA-Z]+)*$/).withMessage('Il nome può contenere solo lettere.'),

    body('lastname')
        .trim().isLength({ max: 50 }).withMessage('Il cognome non puó contenere piú di 50 caratteri.')
        .matches(/^[a-zA-Z]+(?: [a-zA-Z]+)*$/).withMessage('Il cognome può contenere solo lettere.')

], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, username, firstname, lastname } = req.body;

    try {
        const findUser = await db.query("SELECT * FROM users WHERE email = $1", [
            email,
        ]);
    
        if (findUser.rows.length > 0) {
            return res.status(409).json({ message: "L'email inserita é giá in uso." }); 
        } else {
            const hash = await bcrypt.hash(password, saltRounds);
            const result = await db.query(
                "INSERT INTO users (email, password, username, firstname, lastname) VALUES ($1, $2, $3, $4, $5) RETURNING *",
                [email, hash, username, firstname, lastname]
            );
            const user = result.rows[0];
            req.login(user, (err) => {
                console.error(err);
                res.status(201).json({ user: { id: user.id, email: user.email, username: user.username, firstname: user.firstname, lastname: user.lastname } });
            });
        }
    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
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