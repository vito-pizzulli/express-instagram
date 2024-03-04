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
import path from 'path';
import fs from 'fs';
import multer from "multer";

const app = express();
const port = 3001;
const saltRounds = 10;
env.config();

const uploadDirectory = './uploads';
if (!fs.existsSync(uploadDirectory)) {
    fs.mkdirSync(uploadDirectory, { recursive: true });
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const username = req.body.username;
        const fileExtension = path.extname(file.originalname);
        cb(null, `${username}${fileExtension}`);
    }
});

const fileFilter = (req, file, cb) => {
    if (['image/jpeg', 'image/png'].includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Formato non supportato.'), false);
    }
};

const upload = multer({ 
    storage: storage, 
    fileFilter: fileFilter,
    limits: { fileSize: 1024 * 1024 * 5 }
});

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
app.use('/uploads', express.static('uploads'));

const db = new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});
db.connect();

app.get('/api/status', (req, res) => {
    res.json({ isAuthenticated: req.isAuthenticated(), user: req.user });
});

app.post("/api/register", upload.single('profile_pic_url'), [
    body('email')
        .notEmpty().withMessage('Il campo email non puó essere vuoto.').bail()
        .trim()
        .normalizeEmail()
        .isEmail().withMessage('Inserisci un indirizzo email valido.')
        .isLength({ max: 255 }).withMessage('L\'indirizzo email non puó contenere piú di 255 caratteri.'),

    body('password')
        .notEmpty().withMessage('Il campo password non puó essere vuoto.').bail()
        .isLength({ min: 8, max: 255 }).withMessage('La password deve contenere almeno 8 caratteri.')
        .matches(/\d/).withMessage('La password deve contenere almeno un numero.')
        .matches(/[a-z]/).withMessage('La password deve contenere almeno una lettera minuscola.')
        .matches(/[A-Z]/).withMessage('La password deve contenere almeno una lettera maiuscola.')
        .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('La password deve contenere almeno un simbolo speciale.'),

    body('username')
        .notEmpty().withMessage('Il campo username non puó essere vuoto.').bail()
        .trim()
        .toLowerCase()
        .isLength({ min: 3, max: 30 }).withMessage('L\'username deve contenere tra 3 e 30 caratteri.')
        .matches(/^[a-zA-Z0-9_.]+$/).withMessage('L\'username può contenere solo lettere, numeri, underscore e punti.'),

    body('name')
        .notEmpty().withMessage('Il campo nome non puó essere vuoto.').bail()
        .trim()
        .isLength({ max: 50 }).withMessage('Il nome non puó contenere piú di 50 caratteri.')
        .matches(/^[a-zA-Z]+(?: [a-zA-Z]+)*$/).withMessage('Il nome può contenere solo lettere.')

], async (req, res) => {
    const validationErrors = validationResult(req);
    let availabilityErrors = [];
    const { email, password, username, name } = req.body;
    let profileImagePath;

    if (!validationErrors.isEmpty()) {
        return res.status(400).json({ errors: validationErrors.array() });
    }

    if (req.file) {
        profileImagePath = `uploads/${username}${path.extname(req.file.originalname)}`;
    } else {
        return res.status(415).json({ success: false, message: "É necessario caricare un'immagine di profilo." }); 
    }

    try {
        const checkMailAvailable = await db.query("SELECT * FROM users WHERE email = $1", [
            email,
        ]);
    
        if (checkMailAvailable.rows.length > 0) {
            availabilityErrors.push({ msg: `L'email ${email} é giá in uso.` });
        }

        const checkUsernameAvailable = await db.query("SELECT * FROM users WHERE username = $1", [
            username,
        ]);

        if (checkUsernameAvailable.rows.length > 0) {
            availabilityErrors.push({ msg: `L'username ${username} é giá in uso.` });
        }

        if (availabilityErrors.length > 0) {
            return res.status(409).json({ errors: availabilityErrors });
        }

        const hash = await bcrypt.hash(password, saltRounds);
        const result = await db.query(
            "INSERT INTO users (email, password, username, name, profile_pic_url) VALUES ($1, $2, $3, $4, $5) RETURNING *",
            [email, hash, username, name, profileImagePath]
        );
        const user = result.rows[0];
        req.login(user, (err) => {
            
            if (err) {
                console.error(err);
                return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
            }
            res.status(201).json({ success: true, message: 'Registrazione effettuata con successo!', user: user });
        });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
    }
});

app.post("/api/completeRegistration", upload.single('profile_pic_url'), [
    body('username')
        .notEmpty().withMessage('Il campo username non puó essere vuoto.').bail()
        .trim()
        .toLowerCase()
        .isLength({ min: 3, max: 30 }).withMessage('L\'username deve contenere tra 3 e 30 caratteri.')
        .matches(/^[a-zA-Z0-9_.]+$/).withMessage('L\'username può contenere solo lettere, numeri, underscore e punti.'),

    body('name')
        .notEmpty().withMessage('Il campo nome non puó essere vuoto.').bail()
        .trim()
        .isLength({ max: 50 }).withMessage('Il nome non puó contenere piú di 50 caratteri.')
        .matches(/^[a-zA-Z]+(?: [a-zA-Z]+)*$/).withMessage('Il nome può contenere solo lettere.')

], async (req, res) => {
    const validationErrors = validationResult(req);
    let availabilityErrors = [];
    const { email, username, name } = req.body;
    let profileImagePath;

    if (!validationErrors.isEmpty()) {
        return res.status(400).json({ errors: validationErrors.array() });
    }

    if (req.file) {
        profileImagePath = `uploads/${username}${path.extname(req.file.originalname)}`;
    } else {
        return res.status(415).json({ success: false, message: "É necessario caricare un'immagine di profilo." }); 
    }

    try {
        const checkUsernameAvailable = await db.query("SELECT * FROM users WHERE username = $1", [
            username,
        ]);

        if (checkUsernameAvailable.rows.length > 0) {
            availabilityErrors.push({ msg: `L'username ${username} é giá in uso.` });
        }

        if (availabilityErrors.length > 0) {
            return res.status(409).json({ errors: availabilityErrors });
        }

        const findUser = await db.query("SELECT * FROM users WHERE email = $1", [
            email,
        ]);

        if (findUser.rows.length === 0) {
            return res.status(404).json({ success: false, message: "L'utente non é stato trovato." }); 
        }
    
        const result = await db.query(
            "UPDATE users SET username = $1, name = $2, profile_pic_url = $3 WHERE email = $4 RETURNING *",
            [username, name, profileImagePath, email]
        );

        const user = result.rows[0];
        res.status(201).json({ success: true, message: 'Profilo completato con successo!', user: user });
        
    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi" });
    }
});

app.post('/api/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi" });
        }
        if (!user) {
            return res.status(401).json({ success: false, message: "Le credenziali inserite non sono valide." });
        }
        req.login(user, (err) => {
            if (err) {
                return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
            }
            return res.status(200).json({ success: true, message: 'Login effettuato con successo!', user: { id: user.id, email: user.email, username: user.username, name: user.name, profile_pic_url: user.profile_pic_url } });
        });
    })(req, res, next);
});

app.get("/api/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
        }
        res.status(200).json({ success: true, message: "Logout effettuato con successo!" });

    });
});

app.post("/api/updateProfile", upload.single('profile_pic_url'), [
    body('email')
        .optional({ checkFalsy: true })
        .trim()
        .normalizeEmail()
        .isEmail().withMessage('Inserisci un indirizzo email valido.')
        .isLength({ max: 255 }).withMessage('L\'indirizzo email non puó contenere piú di 255 caratteri.'),

    body('password')
        .optional({ checkFalsy: true })
        .isLength({ min: 8, max: 255 }).withMessage('La password deve contenere almeno 8 caratteri.')
        .matches(/\d/).withMessage('La password deve contenere almeno un numero.')
        .matches(/[a-z]/).withMessage('La password deve contenere almeno una lettera minuscola.')
        .matches(/[A-Z]/).withMessage('La password deve contenere almeno una lettera maiuscola.')
        .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('La password deve contenere almeno un simbolo speciale.'),

    body('username')
        .optional({ checkFalsy: true })
        .trim()
        .toLowerCase()
        .isLength({ min: 3, max: 30 }).withMessage('L\'username deve contenere tra 3 e 30 caratteri.')
        .matches(/^[a-zA-Z0-9_.]+$/).withMessage('L\'username può contenere solo lettere, numeri, underscore e punti.'),

    body('name')
        .optional({ checkFalsy: true })
        .trim()
        .isLength({ max: 50 }).withMessage('Il nome non puó contenere piú di 50 caratteri.')
        .matches(/^[a-zA-Z]+(?: [a-zA-Z]+)*$/).withMessage('Il nome può contenere solo lettere.'),

    body('bio')
        .optional({ checkFalsy: true })
        .isLength({ max: 150 }).withMessage('La bio non puó contenere piú di 150 caratteri.')

], async (req, res) => {
    const validationErrors = validationResult(req);
    const { email, password, username, name, bio } = req.body;
    const userId = req.user.id;
    let profileImagePath;
    let availabilityErrors = [];

    if (!validationErrors.isEmpty()) {
        return res.status(400).json({ errors: validationErrors.array() });
    }

    if (req.file) {
        if (username) {
            profileImagePath = `uploads/${username}${path.extname(req.file.originalname)}`;
        } else {
            profileImagePath = `uploads/${req.user.username}${path.extname(req.file.originalname)}`;
        }
        
        fs.unlink(req.user.profile_pic_url, (err) => {
            if (err) {
                console.error('Errore durante l\'eliminazione del file:', err);
            }
        });
    }

    try {
        const checkMailAvailable = await db.query("SELECT * FROM users WHERE email = $1 AND id != $2", [
            email, userId
        ]);

        if (checkMailAvailable.rows.length > 0) {
            availabilityErrors.push({ msg: `L'email ${email} é giá in uso.` });
        }

        const checkUsernameAvailable = await db.query("SELECT * FROM users WHERE username = $1 AND id != $2", [
            username, userId
        ]);

        if (checkUsernameAvailable.rows.length > 0) {
            availabilityErrors.push({ msg: `L'username ${username} é giá in uso.` });
        }

        if (availabilityErrors.length > 0) {
            return res.status(409).json({ errors: availabilityErrors });
        }

        let updateQuery = "UPDATE users SET";
        let queryParams = [];
        let queryCount = 1;

        if (email.trim() !== '' && email !== req.user.email) {
            updateQuery += ` email = $${queryCount},`;
            queryParams.push(email);
            queryCount++;
        }

        if (password.trim() !== '') {
            const hash = await bcrypt.hash(password, saltRounds);
            updateQuery += ` password = $${queryCount},`;
            queryParams.push(hash);
            queryCount++;
        }

        if (username.trim() !== '' && username !== req.user.username) {
            updateQuery += ` username = $${queryCount},`;
            queryParams.push(username);
            queryCount++;
        }

        if (name.trim() !== '' && name !== req.user.name) {
            updateQuery += ` name = $${queryCount},`;
            queryParams.push(name);
            queryCount++;
        }

        if (profileImagePath && profileImagePath !== req.user.profile_pic_url) {
            updateQuery += ` profile_pic_url = $${queryCount},`;
            queryParams.push(profileImagePath);
            queryCount++;
        }

        if (bio !== req.user.bio || bio === '') {
            updateQuery += ` bio = $${queryCount},`;
            queryParams.push(bio);
            queryCount++;
        }

        if (queryCount === 1) {
            return res.status(400).json({ success: false, message: "Nessuna modifica rilevata." });
        }

        updateQuery = updateQuery.slice(0, -1);

        updateQuery += ` WHERE id = $${queryCount}`;
        queryParams.push(userId);

        await db.query(updateQuery, queryParams);

        const updatedUser = await db.query("SELECT email, username, name, profile_pic_url, bio FROM users WHERE id = $1", [userId]);

        const updatedUserInfo = updatedUser.rows[0];
        res.status(200).json({ success: true, message: 'Modifiche salvate con successo!', user: updatedUserInfo });  

    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
    }
});

app.get("/auth/google",
    passport.authenticate("google", {
        scope: ["profile", "email"],
    })
);

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect('http://localhost:3000');
    }
);

passport.use("local",
    new Strategy({
        usernameField: 'email',
        passwordField: 'password',
    }, async (email, password, cb) => {
        try {
            const findUser = await db.query("SELECT * FROM users WHERE email = $1 ", [email]);
            if (findUser.rows.length > 0) {
                const user = findUser.rows[0];
                const storedHashedPassword = user.password;
                bcrypt.compare(password, storedHashedPassword, (err, valid) => {

                if (err) {
                    console.error(err);
                    return cb(err);
                } else {

                    if (valid) {
                    return cb(null, user);
                    } else {
                    return cb(null, false);
                    }
                }
                });
            } else {
                return cb(null, false);
            }
        } catch (err) {
            console.error(err);
            return cb(err);
        }
    })
);

passport.use("google",
    new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3001/auth/google/callback",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    }, async (accessToken, refreshToken, profile, cb) => {
        try {
            const findUser = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);

            if (findUser.rows.length === 0) {
                const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", [profile.email, "google"]);
                cb(null, newUser.rows[0]);
            } else {
                cb(null, findUser.rows[0]);
            }

        } catch (err) {
            console.error(err);
            return cb(err);
        }
    })
);

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