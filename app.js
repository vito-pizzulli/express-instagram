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
import moment from "moment";
import Jimp from "jimp";
import slugify from "slugify";

const app = express();
const port = 3001;
const saltRounds = 10;
env.config();

const usersUploadDirectory = './uploads/users';
const postsUploadDirectory = './uploads/posts';

if (!fs.existsSync(usersUploadDirectory)) {
    fs.mkdirSync(usersUploadDirectory, { recursive: true });
}

if (!fs.existsSync(postsUploadDirectory)) {
    fs.mkdirSync(postsUploadDirectory, { recursive: true });
}

const storage = multer.memoryStorage();

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
app.use('/uploads/users', express.static('uploads/users'));
app.use('/uploads/posts', express.static('uploads/posts'));

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

app.post('/api/register', upload.single('profile_pic_url'), [
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

    if (!validationErrors.isEmpty()) {
        return res.status(400).json({ errors: validationErrors.array() });
    }

    if (req.file) {
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

            const image = await Jimp.read(req.file.buffer);
            const imagePath = `uploads/users/${username}.jpg`;
            await image.writeAsync(imagePath);
    
            const hash = await bcrypt.hash(password, saltRounds);
            const result = await db.query(
                "INSERT INTO users (email, password, username, name, profile_pic_url) VALUES ($1, $2, $3, $4, $5) RETURNING *",
                [email, hash, username, name, imagePath]
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
    } else {
        return res.status(415).json({ success: false, message: "É necessario caricare un'immagine di profilo." }); 
    }
});

app.put('/api/completeRegistration', upload.single('profile_pic_url'), [
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

    if (!validationErrors.isEmpty()) {
        return res.status(400).json({ errors: validationErrors.array() });
    }

    if (req.file) {
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

            const image = await Jimp.read(req.file.buffer);
            const imagePath = `uploads/users/${username}.jpg`;
            await image.writeAsync(imagePath);
        
            const result = await db.query(
                "UPDATE users SET username = $1, name = $2, profile_pic_url = $3 WHERE email = $4 RETURNING *",
                [username, name, imagePath, email]
            );
    
            const user = result.rows[0];
            res.status(201).json({ success: true, message: 'Profilo completato con successo!', user: user });
            
        } catch (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi" });
        }
    } else {
        return res.status(415).json({ success: false, message: "É necessario caricare un'immagine di profilo." }); 
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

app.post('/api/logout', (req, res) => {
    req.logout(function (err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
        }
        res.status(200).json({ success: true, message: "Logout effettuato con successo!" });

    });
});

app.patch('/api/updateProfile', upload.single('profile_pic_url'), [
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
    let availabilityErrors = [];
    let imagePath;

    if (!validationErrors.isEmpty()) {
        return res.status(400).json({ errors: validationErrors.array() });
    }

    if (req.file) {
        if (username) {
            imagePath = `uploads/users/${username}.jpg`;
        } else {
            imagePath = `uploads/users/${req.user.username}.jpg`;
        }

        try {
            const image = await Jimp.read(req.file.buffer);
            await image.writeAsync(imagePath);

            if (imagePath !== req.user.profile_pic_url) {
                fs.unlink(req.user.profile_pic_url, (err) => {
                    if (err) {
                        console.error('Errore durante l\'eliminazione del file:', err);
                    }
                });
            };

        } catch {
            console.error('Errore durante il processing dell\'immagine:', err);
        }
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

        if (username !== req.user.profile_pic_url && !req.file) {
            const oldPath = req.user.profile_pic_url;
            const newPath = `uploads/users/${username}.jpg`;
            fs.rename(oldPath, newPath, (err) => {
                if (err) {
                    console.error('Errore durante la rinomina del file:', err);
                }
            });
            imagePath = newPath;
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

        if (imagePath) {
            updateQuery += ` profile_pic_url = $${queryCount},`;
            queryParams.push(imagePath);
            queryCount++;
        }

        if (bio !== req.user.bio || (bio === '' && req.user.bio !== '')) {
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

app.delete('/api/deleteProfile', async (req, res) => {
    const userId = req.user.id;

    try {
        await db.query('BEGIN');

        const postsImages = await db.query('SELECT image_url FROM posts WHERE user_id = $1', [userId]);
        postsImages.rows.forEach(row => {
            fs.unlink(row.image_url, (err) => {
                if (err) {
                    console.error('Errore durante l\'eliminazione del file:', err);
                }
            });
        });

        fs.unlink(req.user.profile_pic_url, (err) => {
            if (err) {
                console.error('Errore durante l\'eliminazione del file:', err);
            }
        });

        await db.query('DELETE FROM posts WHERE user_id = $1', [userId]);
        await db.query('DELETE FROM users WHERE id = $1', [userId]);
        await db.query('COMMIT');

        req.logout(function (err) {
            if (err) {
                console.error(err);
                return res.status(500).json({ success: false, message: "Errore interno del server. Riprova più tardi." });
            }
            res.status(200).json({ success: true, message: "Account eliminato con successo!" });
        });
    } catch (err) {
        await db.query('ROLLBACK');
        console.error('Errore durante l\'eliminazione dell\'utente e dei suoi post:', err);
        res.status(500).json({ success: false, message: "Errore interno del server. Riprova più tardi." });
    }
});

app.get('/api/posts', async (req, res) => {
    try {
        const result = await db.query("SELECT posts.id, posts.user_id, posts.image_url, posts.description, posts.location, posts.slug, posts.created_at, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY posts.created_at DESC");
        if (result.rows.length > 0) {
            res.status(200).json(result.rows);
        } else {
            res.status(404).json({ message: "Nessun post trovato." });
        }

    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
    };
});

app.get('/api/posts/:username/:slug', async (req, res) => {
    const { slug } = req.params;

    try {
        const result = await db.query("SELECT posts.id, posts.user_id, posts.image_url, posts.description, posts.location, posts.slug, posts.created_at, users.username FROM posts JOIN users ON posts.user_id = users.id WHERE posts.slug = $1", [slug]);

        if (result.rows.length > 0) {
            return res.status(200).json(result.rows[0]);
        } else {
            return res.status(404).json({ message: "Post non trovato." });
        }
    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
    }
});

app.get('/api/:username', async (req, res) => {
    const { username } = req.params;
    try {
        const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
        if (result.rows.length > 0) {
            return res.status(200).json(result.rows);
        } else {
            return res.status(404).json({ message: "Utente non trovato." });
        }
    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
    }
});

app.get('/api/userPosts/:username', async (req, res) => {
    const { username } = req.params;
    try {
        const result = await db.query("SELECT posts.id, posts.user_id, posts.image_url, posts.description, posts.location, posts.slug, posts.created_at, users.username FROM posts JOIN users ON posts.user_id = users.id WHERE users.username = $1 ORDER BY posts.created_at DESC", [username]);
        if (result.rows.length > 0) {
            res.status(200).json(result.rows);
        } else {
            res.status(404).json({ message: "Nessun post trovato." });
        }

    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
    };
});

app.post('/api/addPost', upload.single('image_url'), [
    body('description')
        .optional({ checkFalsy: true })
        .isLength({ max: 255 }).withMessage('La bio non puó contenere piú di 255 caratteri.'),

    body('location')
        .optional({ checkFalsy: true })
        .isLength({ max: 255 }).withMessage('Il luogo non puó contenere piú di 255 caratteri.')

], async (req, res) => {
    const validationErrors = validationResult(req);
    const { description, location } = req.body;
    const user_id = req.user.id;

    if (!validationErrors.isEmpty()) {
        return res.status(400).json({ errors: validationErrors.array() });
    }

    if (req.file) {
        try {
            const timestamp = moment().format('DDMMYYYY_HHmmss');

            const slugBase = `${req.user.id}_${timestamp}`;
            const slug = slugify(slugBase, { lower: true, strict: true });

            const image = await Jimp.read(req.file.buffer);
            const imagePath = `uploads/posts/${req.user.id}${timestamp}.jpg`;
            await image.writeAsync(imagePath);

            const result = await db.query(
                'INSERT INTO posts (user_id, image_url, description, location, slug) VALUES ($1, $2, $3, $4, $5) RETURNING *',
                [user_id, imagePath, description, location, slug]);
            const post = result.rows[0];
    
            res.status(201).json({ success: true, message: 'Pubblicazione effettuata con successo!', post: post });
    
        } catch (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
        }
        
    } else {
        return res.status(415).json({ success: false, message: "É necessario caricare un'immagine per pubblicare il post." }); 
    }
});

app.delete('/api/deletePost/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const result = await db.query('SELECT image_url FROM posts WHERE id = $1', [id]);

        const imageUrl = result.rows[0].image_url;
        fs.unlink(imageUrl, (err) => {
            if (err) {
                console.error('Errore durante l\'eliminazione del file:', err);
            }
        });
        await db.query('DELETE FROM posts WHERE id = $1', [id]);
        res.status(200).json({ success: true, message: "Post eliminato con successo!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Errore interno del server. Riprova più tardi." });
    }
});

app.get('/auth/google',
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