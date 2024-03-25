// Importing necessary libraries.
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
import fs from 'fs';
import multer from "multer";
import moment from "moment";
import Jimp from "jimp";
import slugify from "slugify";

// Initializing Express application.
const app = express();

// Server port number.
const port = 3001;

// Number of rounds to use for bcrypt salt generation.
const saltRounds = 10;

// Loading environment variables from .env file.
env.config();

// Directories for user and post uploads.
const usersUploadDirectory = './uploads/users';
const postsUploadDirectory = './uploads/posts';

// Ensure the upload directories exist, create them if they don't.
if (!fs.existsSync(usersUploadDirectory)) {
    fs.mkdirSync(usersUploadDirectory, { recursive: true });
}
if (!fs.existsSync(postsUploadDirectory)) {
    fs.mkdirSync(postsUploadDirectory, { recursive: true });
}

// Configuring storage for file uploads to keep files in memory.
const storage = multer.memoryStorage();

// File filter to restrict uploaded file types.
const fileFilter = (req, file, cb) => {
    if (['image/jpeg', 'image/png'].includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Formato non supportato.'), false);
    }
};

// Configuring multer for file upload with defined storage, file filter, and size limits.
const upload = multer({ 
    storage: storage, 
    fileFilter: fileFilter,
    limits: { fileSize: 1024 * 1024 * 5 }
});

// Configuring session middleware with options for cookie management and security.
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

// Middleware to parse JSON and urlencoded data and to enable CORS.
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: 'http://localhost:3000', // Setting CORS to accept requests from our front-end domain.
    credentials: true // Allowing credentials (cookies, authorization headers, etc) to be sent with the requests.
}));

// Initializing Passport for authentication and session management.
app.use(passport.initialize());
app.use(passport.session());

// Serve static files from uploads directories.
app.use('/uploads/users', express.static('uploads/users'));
app.use('/uploads/posts', express.static('uploads/posts'));

// Database client setup using configuration from environment variables.
const db = new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Establishing connection to the database.
db.connect();

// API endpoint to check the authentication status and retrieve the current user.
app.get('/api/status', (req, res) => {
    res.json({ isAuthenticated: req.isAuthenticated(), user: req.user });
});

// API endpoint to register a new user.
app.post('/api/register', upload.single('profile_pic_url'), [

    // Validate and sanitize the email field.
    body('email')
        .notEmpty().withMessage('Il campo e-mail non puó essere vuoto.').bail()
        .trim()
        .normalizeEmail()
        .isEmail().withMessage('Inserisci un indirizzo e-mail valido.')
        .isLength({ max: 255 }).withMessage('L\'indirizzo e-mail non puó contenere piú di 255 caratteri.'),

    // Validate the password field.
    body('password')
        .notEmpty().withMessage('Il campo password non puó essere vuoto.').bail()
        .isLength({ min: 8, max: 255 }).withMessage('La password deve contenere almeno 8 caratteri.')
        .matches(/\d/).withMessage('La password deve contenere almeno un numero.')
        .matches(/[a-z]/).withMessage('La password deve contenere almeno una lettera minuscola.')
        .matches(/[A-Z]/).withMessage('La password deve contenere almeno una lettera maiuscola.')
        .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('La password deve contenere almeno un simbolo speciale.'),

    // Validate and sanitize the username field.
    body('username')
        .notEmpty().withMessage('Il campo nome utente non puó essere vuoto.').bail()
        .trim()
        .toLowerCase()
        .isLength({ min: 3, max: 30 }).withMessage('Il nome utente deve contenere tra 3 e 30 caratteri.')
        .matches(/^[a-zA-Z0-9_.]+$/).withMessage('Il nome utente può contenere solo lettere, numeri, underscore e punti.'),

    // Validate and sanitize the name field.
    body('name')
        .notEmpty().withMessage('Il campo nome non puó essere vuoto.').bail()
        .trim()
        .isLength({ max: 50 }).withMessage('Il nome non puó contenere piú di 50 caratteri.')
        .matches(/^[a-zA-Z]+(?: [a-zA-Z]+)*$/).withMessage('Il nome può contenere solo lettere.')

], async (req, res) => {
    const validationErrors = validationResult(req);
    let availabilityErrors = [];
    const { email, password, username, name } = req.body;

    // If validation errors exist, return them with a 400 status.
    if (!validationErrors.isEmpty()) {
        return res.status(400).json({ errors: validationErrors.array() });
    }

    if (req.file) {
        try {
            // Check if the email is already used.
            const checkMailAvailable = await db.query("SELECT * FROM users WHERE email = $1", [
                email,
            ]);
            
            // If the email is taken, add an error.
            if (checkMailAvailable.rows.length > 0) {
                availabilityErrors.push({ msg: `L'e-mail ${email} é giá in uso.` });
            }
            
            // Check if the username is already taken.
            const checkUsernameAvailable = await db.query("SELECT * FROM users WHERE username = $1", [
                username,
            ]);
    
            // If the username is taken, add an error.
            if (checkUsernameAvailable.rows.length > 0) {
                availabilityErrors.push({ msg: `Il nome utente ${username} é giá in uso.` });
            }
            
            // If there are any availability errors, return them with a 409 status.
            if (availabilityErrors.length > 0) {
                return res.status(409).json({ errors: availabilityErrors });
            }

            // Process the profile image.
            const image = await Jimp.read(req.file.buffer);
            const imagePath = `uploads/users/${username}.jpg`;
            await image.writeAsync(imagePath);
    
            // Hash the password.
            const hash = await bcrypt.hash(password, saltRounds);

            // Insert the new user into the database.
            const result = await db.query(
                "INSERT INTO users (email, password, username, name, profile_pic_url) VALUES ($1, $2, $3, $4, $5) RETURNING *",
                [email, hash, username, name, imagePath]
            );
            const user = result.rows[0];

            // Log in the user automatically after registration with the Passport req.login method.
            req.login(user, (err) => {
                
                if (err) {
                    console.error(err);

                    // If login fails, return a server error.
                    return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
                }

                // Respond with a success message and the user info.
                res.status(201).json({ success: true, message: 'Iscrizione effettuata con successo!', user: user });
            });
    
        } catch (err) {
            console.error(err);
            // If there are any unexpexted error during the process, return a server error.
            return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
        }
    } else {

        // If no profile picture is uploaded, return an error.
        return res.status(415).json({ success: false, message: "É necessario caricare un'immagine di profilo." }); 
    }
});

// API endpoint to complete the profile of the user authenticated with Google OAuth.
app.put('/api/completeRegistration', upload.single('profile_pic_url'), [

    // Validate and sanitize the username field.
    body('username')
        .notEmpty().withMessage('Il campo nome utente non puó essere vuoto.').bail()
        .trim()
        .toLowerCase()
        .isLength({ min: 3, max: 30 }).withMessage('Il nome utente deve contenere tra 3 e 30 caratteri.')
        .matches(/^[a-zA-Z0-9_.]+$/).withMessage('Il nome utente può contenere solo lettere, numeri, underscore e punti.'),

    // Validate and sanitize the name field.
    body('name')
        .notEmpty().withMessage('Il campo nome non puó essere vuoto.').bail()
        .trim()
        .isLength({ max: 50 }).withMessage('Il nome non puó contenere piú di 50 caratteri.')
        .matches(/^[a-zA-Z]+(?: [a-zA-Z]+)*$/).withMessage('Il nome può contenere solo lettere.')

], async (req, res) => {
    const validationErrors = validationResult(req);
    let availabilityErrors = [];
    const { email, username, name } = req.body;

    // If validation errors exist, return them with a 400 status.
    if (!validationErrors.isEmpty()) {
        return res.status(400).json({ errors: validationErrors.array() });
    }

    if (req.file) {
        try {

            // Check if the username is already taken.
            const checkUsernameAvailable = await db.query("SELECT * FROM users WHERE username = $1", [
                username,
            ]);
            
            // If the username is taken, add an error.
            if (checkUsernameAvailable.rows.length > 0) {
                availabilityErrors.push({ msg: `Il nome utente ${username} é giá in uso.` });
            }
            
            // If there are any availability errors, return them with a 409 status.
            if (availabilityErrors.length > 0) {
                return res.status(409).json({ errors: availabilityErrors });
            }
            
            // Check if the user exists.
            const findUser = await db.query("SELECT * FROM users WHERE email = $1", [
                email,
            ]);
            
            // If the user is not found, return an error with a 404 status.
            if (findUser.rows.length === 0) {
                return res.status(404).json({ success: false, message: "L'utente non é stato trovato." }); 
            }

            // Process the profile image.
            const image = await Jimp.read(req.file.buffer);
            const imagePath = `uploads/users/${username}.jpg`;
            await image.writeAsync(imagePath);
        
            // Update the user into the database.
            const result = await db.query(
                "UPDATE users SET username = $1, name = $2, profile_pic_url = $3 WHERE email = $4 RETURNING *",
                [username, name, imagePath, email]
            );
    
            const user = result.rows[0];

            // Respond with a success message and the user info.
            res.status(201).json({ success: true, message: 'Iscrizione completata con successo!', user: user });
            
        } catch (err) {
            console.error(err);

            // If there are any unexpexted error during the process, return a server error.
            return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi" });
        }
    } else {
        // If no profile picture is uploaded, return an error.
        return res.status(415).json({ success: false, message: "É necessario caricare un'immagine di profilo." }); 
    }
});

// API endpoint to login an existing user.
app.post('/api/login', (req, res, next) => {

    // Passport.authenticate middleware is invoked with the 'local' strategy, it checks the submitted credentials against the database.
    passport.authenticate('local', (err, user, info) => {

        // If there's an authentication error, handle it by returning a server error response.
        if (err) {
            return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi" });
        }

        // If the user is not found or the password does not match, return an unauthorized response.
        if (!user) {
            return res.status(401).json({ success: false, message: "Le credenziali inserite non sono valide." });
        }

        // On successful authentication, log in the user with the Passport req.login method.
        req.login(user, (err) => {

            if (err) {

                // If login fails, return a server error.
                return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
            }

            // Respond with a success message and the user info.
            return res.status(200).json({ success: true, message: 'Login effettuato con successo!', user: { id: user.id, email: user.email, username: user.username, name: user.name, profile_pic_url: user.profile_pic_url } });
        });
    })(req, res, next);
});

// API endpoint to logout the authenticated user.
app.post('/api/logout', (req, res) => {

    // Passport req.logout method is called to log the user out.
    req.logout(function (err) {
        if (err) {
            console.error(err);

            // If logout fails, return a server error.
            return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
        }

        // Respond with a success message.
        res.status(200).json({ success: true, message: "Logout effettuato con successo!" });

    });
});

// API endpoint to update the authenticated user.
app.patch('/api/updateProfile', upload.single('profile_pic_url'), [

    // All fields are optional because the user is not obligated to update all of them.

    // Validate and sanitize the email field.
    body('email')
        .optional({ checkFalsy: true })
        .trim()
        .normalizeEmail()
        .isEmail().withMessage('Inserisci un indirizzo e-mail valido.')
        .isLength({ max: 255 }).withMessage('L\'indirizzo e-mail non puó contenere piú di 255 caratteri.'),

    // Validate the password field.
    body('password')
        .optional({ checkFalsy: true })
        .isLength({ min: 8, max: 255 }).withMessage('La password deve contenere almeno 8 caratteri.')
        .matches(/\d/).withMessage('La password deve contenere almeno un numero.')
        .matches(/[a-z]/).withMessage('La password deve contenere almeno una lettera minuscola.')
        .matches(/[A-Z]/).withMessage('La password deve contenere almeno una lettera maiuscola.')
        .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('La password deve contenere almeno un simbolo speciale.'),

    // Validate and sanitize the username field.
    body('username')
        .optional({ checkFalsy: true })
        .trim()
        .toLowerCase()
        .isLength({ min: 3, max: 30 }).withMessage('Il nome utente deve contenere tra 3 e 30 caratteri.')
        .matches(/^[a-zA-Z0-9_.]+$/).withMessage('Il nome utente può contenere solo lettere, numeri, underscore e punti.'),

    // Validate and sanitize the name field.
    body('name')
        .optional({ checkFalsy: true })
        .trim()
        .isLength({ max: 50 }).withMessage('Il nome non puó contenere piú di 50 caratteri.')
        .matches(/^[a-zA-Z]+(?: [a-zA-Z]+)*$/).withMessage('Il nome può contenere solo lettere.'),

    // Validate the bio field.
    body('bio')
        .optional({ checkFalsy: true })
        .isLength({ max: 150 }).withMessage('La bio non puó contenere piú di 150 caratteri.')

], async (req, res) => {
    const validationErrors = validationResult(req);
    const { email, password, username, name, bio } = req.body;
    const userId = req.user.id;
    let availabilityErrors = [];
    let imagePath;

    // If validation errors exist, return them with a 400 status.
    if (!validationErrors.isEmpty()) {
        return res.status(400).json({ errors: validationErrors.array() });
    }

    if (req.file) {

        // Determine the path where the new profile picture will be stored.
        // If a new username is provided, use it to create the file path.
        if (username) {
            imagePath = `uploads/users/${username}.jpg`;
            
        // Otherwise, use the current username from the user's session.
        } else {
            imagePath = `uploads/users/${req.user.username}.jpg`;
        }

        try {
            // Attempt to read the image from the uploaded file's buffer.
            const image = await Jimp.read(req.file.buffer);

            // Once read successfully, write the image at the specified path.
            await image.writeAsync(imagePath);

            // Check if the new image path is different from the existing profile picture URL.
            if (imagePath !== req.user.profile_pic_url) {

                // If the paths are different, delete the old image file.
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
        // Check if the email is already used.
        const checkMailAvailable = await db.query("SELECT * FROM users WHERE email = $1 AND id != $2", [
            email, userId
        ]);

        // If the email is taken, add an error.
        if (checkMailAvailable.rows.length > 0) {
            availabilityErrors.push({ msg: `L'e-mail ${email} é giá in uso.` });
        }

        // Check if the username is already taken.
        const checkUsernameAvailable = await db.query("SELECT * FROM users WHERE username = $1 AND id != $2", [
            username, userId
        ]);
        
        // If the username is taken, add an error.
        if (checkUsernameAvailable.rows.length > 0) {
            availabilityErrors.push({ msg: `Il nome utente ${username} é giá in uso.` });
        }

        // If there are any availability errors, return them with a 409 status.
        if (availabilityErrors.length > 0) {
            return res.status(409).json({ errors: availabilityErrors });
        }

        // Check if the new username differs from the one used in the current profile picture URL and there's no new file uploaded.
        if (username !== req.user.profile_pic_url && !req.file) {

            // Save the old path of the profile picture.
            const oldPath = req.user.profile_pic_url;

            // Define the new path based on the new username.
            const newPath = `uploads/users/${username}.jpg`;

            // Rename the file from the old path to the new path.
            fs.rename(oldPath, newPath, (err) => {
                if (err) {
                    console.error('Errore durante la rinomina del file:', err);
                }
            });

            // Update the imagePath to be the newPath to reflect the change.
            imagePath = newPath;
        }

        let updateQuery = "UPDATE users SET";
        let queryParams = [];
        let queryCount = 1;

        // Check if the email field is not empty, and if it's different from the current email.
        if (email.trim() !== '' && email !== req.user.email) {
            updateQuery += ` email = $${queryCount},`; // Append email field to the update query.
            queryParams.push(email); // Add email to the parameters array.
            queryCount++; // Increment the placeholder count.
        }

        // Check if the password field is not empty.
        if (password.trim() !== '') {
            const hash = await bcrypt.hash(password, saltRounds); // Hash the password.
            updateQuery += ` password = $${queryCount},`; // Append password field to the update query.
            queryParams.push(hash); // Add password to the parameters array.
            queryCount++; // Increment the placeholder count.
        }

        // Check if the username field is not empty, and if it's different from the current username.
        if (username.trim() !== '' && username !== req.user.username) {
            updateQuery += ` username = $${queryCount},`; // Append username field to the update query.
            queryParams.push(username); // Add username to the parameters array.
            queryCount++; // Increment the placeholder count.
        }

        // Check if the name field is not empty, and if it's different from the current name.
        if (name.trim() !== '' && name !== req.user.name) {
            updateQuery += ` name = $${queryCount},`; // Append name field to the update query.
            queryParams.push(name); // Add name to the parameters array.
            queryCount++; // Increment the placeholder count.
        }

        // Check if imagePath is set (meaning there's a new profile picture).
        if (imagePath) {
            updateQuery += ` profile_pic_url = $${queryCount},`; // Append profile_pic_url field to the update query.
            queryParams.push(imagePath); // Add imagePath to the parameters array.
            queryCount++; // Increment the placeholder count.
        }

        // Check if the bio has been changed or explicitly cleared.
        if (bio !== req.user.bio || (bio === '' && req.user.bio !== '')) {
            updateQuery += ` bio = $${queryCount},`; // Append bio field to the update query.
            queryParams.push(bio); // Add bio to the parameters array.
            queryCount++; // Increment the placeholder count.
        }

        // Remove the last comma from the query.
        updateQuery = updateQuery.slice(0, -1);

        // Specify the user to update by ID.
        updateQuery += ` WHERE id = $${queryCount}`;

        // Add user ID to the parameters array.
        queryParams.push(userId);

        // Execute the update query with parameters.
        await db.query(updateQuery, queryParams);

        // Update the user into the database.
        const updatedUser = await db.query("SELECT email, username, name, profile_pic_url, bio FROM users WHERE id = $1", [userId]);

        const updatedUserInfo = updatedUser.rows[0];

        // Respond with a success message and the updated user info.
        res.status(200).json({ success: true, message: 'Modifiche salvate con successo!', user: updatedUserInfo });  

    } catch (err) {
        console.error(err);

        // If there are any unexpexted error during the process, return a server error.
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
    }
});

// API endpoint to delete the authenticated user with all its associated data.
app.delete('/api/deleteProfile', async (req, res) => {

    // Check if the user is authenticated and has an existing ID.
    if (!req.user || !req.user.id) {
        return res.status(403).json({ success: false, message: "Utente non autenticato o account non esistente." });
    }

    // Get the user's ID from the request.
    const userId = req.user.id;

    try {

        // Start a database transaction.
        await db.query('BEGIN');

        // Select all image URLs associated with the user's posts.
        const result = await db.query('SELECT image_url FROM posts WHERE user_id = $1', [userId]);

        // For each image URL, attempt to delete the file.
        result.rows.forEach(row => {
            fs.unlink(row.image_url, (err) => {
                if (err) {
                    console.error('Errore durante l\'eliminazione del file:', err);
                }
            });
        });

        // Attempt to delete the user's profile picture.
        fs.unlink(req.user.profile_pic_url, (err) => {
            if (err) {
                console.error('Errore durante l\'eliminazione del file:', err);
            }
        });

        // Delete all posts associated with the user from the database.
        await db.query('DELETE FROM posts WHERE user_id = $1', [userId]);

        // Delete the user's account from the database.
        await db.query('DELETE FROM users WHERE id = $1', [userId]);

        // Commit the transaction.
        await db.query('COMMIT');

        // On successful account and associated data deletion, log out the user with the Passport req.logout method.
        req.logout(function (err) {
            if (err) {
                console.error(err);
                return res.status(500).json({ success: false, message: "Errore interno del server. Riprova più tardi." });
            }

            // Respond with a success message.
            res.status(200).json({ success: true, message: "Account eliminato con successo!" });
        });

    } catch (err) {

        // If an error occurs, roll back the transaction.
        await db.query('ROLLBACK');
        console.error('Errore durante l\'eliminazione dell\'utente e dei suoi post:', err);

        // Respond with a server error message.
        res.status(500).json({ success: false, message: "Errore interno del server. Riprova più tardi." });
    }
});

// API endpoint to get all the existing posts.
app.get('/api/posts', async (req, res) => {
    try {

        // Query the database to select all posts (ordered by their creation date in descending order) and the username, profile picture URL of the user who made each post.
        const result = await db.query("SELECT posts.id, posts.user_id, posts.image_url, posts.description, posts.location, posts.slug, posts.created_at, users.username, users.profile_pic_url FROM posts JOIN users ON posts.user_id = users.id ORDER BY posts.created_at DESC");

        // If the query returns rows, it means posts were found. The rows are sent back to the client as a JSON response.
        if (result.rows.length > 0) {
            res.status(200).json(result.rows);
        
        // If no posts are found, respond with a 404 status code and a message.
        } else {
            res.status(404).json({ message: "Nessun post trovato." });
        }

    } catch (err) {
        console.error(err);

        // If there are any unexpexted error during the process, return a server error.
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
    };
});

// API endpoint to get a specific post by its slug.
app.get('/api/posts/:username/:slug', async (req, res) => {

    // Extracts the slug from the URL parameters.
    const { slug } = req.params;

    try {

        // Query the database to select a specific post by its slug, and the username and profile picture URL of the user who created the post.
        const result = await db.query("SELECT posts.id, posts.user_id, posts.image_url, posts.description, posts.location, posts.slug, posts.created_at, users.username, users.profile_pic_url FROM posts JOIN users ON posts.user_id = users.id WHERE posts.slug = $1", [slug]);

        // If the query returns rows, it means the post was found. The first and only row is sent back to the client as a JSON response.
        if (result.rows.length > 0) {
            return res.status(200).json(result.rows[0]);

        // If the post isn't found, respond with a 404 status code and a message.
        } else {
            return res.status(404).json({ message: "Post non trovato." });
        }

    } catch (err) {
        console.error(err);

        // If there are any unexpexted error during the process, return a server error.
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
    }
});

// API endpoint to get a specific user by its username.
app.get('/api/:username', async (req, res) => {

    // Extracts the username from the URL parameters.
    const { username } = req.params;

    try {

        // Query the database to select a specific user by its username.
        const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);

        // If the query returns rows, it means the user was found. The first and only row is sent back to the client as a JSON response.
        if (result.rows.length > 0) {
            return res.status(200).json(result.rows[0]);
        
        // If the user isn't found, respond with a 404 status code and a message.
        } else {
            return res.status(404).json({ message: "Utente non trovato." });
        }
    } catch (err) {
        console.error(err);

        // If there are any unexpexted error during the process, return a server error.
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
    }
});

// API endpoint to get all posts of a specific user by its username.
app.get('/api/userPosts/:username', async (req, res) => {

    // Extracts the username from the URL parameters.
    const { username } = req.params;

    try {

        // Query the database to select all posts (ordered by their ceration date in descending order) made by a user with the specified username.
        const result = await db.query("SELECT posts.id, posts.user_id, posts.image_url, posts.description, posts.location, posts.slug, posts.created_at, users.username FROM posts JOIN users ON posts.user_id = users.id WHERE users.username = $1 ORDER BY posts.created_at DESC", [username]);

        // If the query returns rows, it means posts were found. The rows are sent back to the client as a JSON response.
        if (result.rows.length > 0) {
            res.status(200).json(result.rows);

        // If no posts are found, respond with a 404 status code and a message.
        } else {
            res.status(404).json({ message: "Nessun post trovato." });
        }

    } catch (err) {
        console.error(err);

        // If there are any unexpexted error during the process, return a server error.
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
    };
});

// API endpoint to get a specific user by word.
app.get('/api/searchUsers/:wordToSearch', async (req, res) => {

    // Extracts the word from the URL parameters.
    const { wordToSearch } = req.params;

    try {
        // Query the database to select a specific user performing a case-insensitive search for usernames that contain the search word. Any characters are allowed to precede or follow the search word and the results are sorted by the length of the username, for shortest to longest.
        const result = await db.query("SELECT * FROM users WHERE username ILIKE '%' || $1 || '%' ORDER BY LENGTH(username)", [wordToSearch]);

        // If the query returns rows, it means users were found. The rows are sent back to the client as a JSON response.
        if (result.rows.length > 0) {
            res.status(200).json(result.rows);

        // If no users are found, respond with a 404 status code and a message.
        } else {
            res.status(404).json({ message: "Nessun utente trovato." });
        }

    } catch (err) {
        console.error(err);

        // If there are any unexpexted error during the process, return a server error.
        return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
    };
});

// API endpoint to add a new post.
app.post('/api/addPost', upload.single('image_url'), [

    // Validate the description field.
    body('description')
        .optional({ checkFalsy: true })
        .isLength({ max: 255 }).withMessage('La bio non puó contenere piú di 255 caratteri.'),

    // Validate the location field.
    body('location')
        .optional({ checkFalsy: true })
        .isLength({ max: 255 }).withMessage('Il luogo non puó contenere piú di 255 caratteri.')

], async (req, res) => {
    const validationErrors = validationResult(req);
    const { description, location } = req.body;
    const user_id = req.user.id;

    // If validation errors exist, return them with a 400 status.
    if (!validationErrors.isEmpty()) {
        return res.status(400).json({ errors: validationErrors.array() });
    }

    if (req.file) {
        try {

            // Generates a timestamp.
            const timestamp = moment().format('DDMMYYYY_HHmmss');

            // Constructs a base string for the slug using the user's ID and the timestamp, ensuring it's unique.
            const slugBase = `${req.user.id}_${timestamp}`;

            // Uses slugify to convert the base string into a URL-friendly slug, making it lowercase and removing special characters.
            const slug = slugify(slugBase, { lower: true, strict: true });

            // Process the profile image.
            const image = await Jimp.read(req.file.buffer);
            const imagePath = `uploads/posts/${req.user.id}${timestamp}.jpg`;
            await image.writeAsync(imagePath);

            // Insert the new post into the database.
            const result = await db.query(
                'INSERT INTO posts (user_id, image_url, description, location, slug) VALUES ($1, $2, $3, $4, $5) RETURNING *',
                [user_id, imagePath, description, location, slug]);
            const post = result.rows[0];
                
            // Respond with a success message and the post info.
            res.status(201).json({ success: true, message: 'Post pubblicato con successo!', post: post });
    
        } catch (err) {
            console.error(err);

            // If there are any unexpexted error during the process, return a server error.
            return res.status(500).json({ success: false, message: "Errore interno del server. Riprova piú tardi." });
        }
        
    } else {
        
        // If no post image is uploaded, return an error.
        return res.status(415).json({ success: false, message: "É necessario caricare un'immagine per pubblicare il post." }); 
    }
});

// API endpoint to delete a specific post by its id.
app.delete('/api/deletePost/:id', async (req, res) => {

    // Extracts the id from the URL parameters.
    const { id } = req.params;

    try {

        // Query the database to select the image URL of a specific post by its id.
        const result = await db.query('SELECT image_url FROM posts WHERE id = $1', [id]);

        // If the post exists, retrieve its image URL.
        if (result.rows.length > 0) {
            const imageUrl = result.rows[0].image_url;

            // Delete the image file associated with the post.
            fs.unlink(imageUrl, (err) => {
                if (err) {
                    console.error('Errore durante l\'eliminazione del file:', err);
                }
                });

            // Query the database delete the specific post by its id.
            await db.query('DELETE FROM posts WHERE id = $1', [id]);

            // Respond with a success message.
            res.status(200).json({ success: true, message: "Post eliminato con successo!" });
        } else {

            // If the post isn't found, respond with a 404 status code and a message.
            res.status(404).json({ success: false, message: "Post non trovato." });
        }

    } catch (err) {
        console.error(err);

        // If there are any unexpexted error during the process, return a server error.
        res.status(500).json({ success: false, message: "Errore interno del server. Riprova più tardi." });
    }
});

// Endpoint for initiating Google OAuth login process.
app.get('/auth/google',

    // Use Passport to authenticate with Google strategy.
    passport.authenticate("google", {

        // Request access to the user's profile and email from Google.
        scope: ["profile", "email"],
    })
);

// Endpoint for handling the callback after Google has authenticated the user.
app.get('/auth/google/callback', 

    // Use Passport to handle the authentication with Google's callback.
    passport.authenticate('google', { failureRedirect: '/login' }),

    // Once authentication is successful, redirect the user.
    (req, res) => {
        res.redirect('http://localhost:3000');
    }
);

// Configuring the Passport local strategy for email and password authentication.
passport.use("local",
    new Strategy({

        // Customizing Passport's expected username and password fields to use email and password.
        usernameField: 'email',
        passwordField: 'password',
    }, async (email, password, cb) => {

        try {

            // Query the database to find a user with the provided email.
            const findUser = await db.query("SELECT * FROM users WHERE email = $1 ", [email]);

            // If a user is found, extract the user and their stored hashed password.
            if (findUser.rows.length > 0) {
                const user = findUser.rows[0];
                const storedHashedPassword = user.password;

                // Use bcrypt to compare the provided password with the stored hashed password.
                bcrypt.compare(password, storedHashedPassword, (err, valid) => {

                if (err) {
                    console.error(err);
                    return cb(err);

                } else {

                    // If the password is valid, return the user object through the callback.
                    if (valid) {
                    return cb(null, user);

                    // If the password is invalid, return false indicating authentication failure.
                    } else {
                    return cb(null, false);
                    }
                }
                });

            } else {

                // If no user is found with the provided email, return false indicating authentication failure.
                return cb(null, false);
            }
        } catch (err) {
            console.error(err);
            return cb(err);
        }
    })
);

// Configuring Passport to use the Google OAuth 2.0 strategy for authentication.
passport.use("google",
    new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID, // Google client ID from Google Developer Console.
        clientSecret: process.env.GOOGLE_CLIENT_SECRET, // Google client secret from Google Developer Console.
        callbackURL: "http://localhost:3001/auth/google/callback", // The URL to which Google will redirect the user after user consent.
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" // Override URL for fetching user profile. This ensures we are using the latest version.
    }, async (accessToken, refreshToken, profile, cb) => {

        // This function is called after Google has authenticated the user.
        try {

            // Query the database to find an existing user with the email address from the Google profile.
            const findUser = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);

            // If the user does not exist, create a new user in the database.
            if (findUser.rows.length === 0) {
                const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", [profile.email, "google"]);

                // Pass the new user object to the callback function.
                cb(null, newUser.rows[0]);

            } else {

                // If the user exists, pass the existing user object to the callback function.
                cb(null, findUser.rows[0]);
            }

        } catch (err) {
            console.error(err);
            return cb(err);
        }
    })
);

// Passport serialization setup.
passport.serializeUser((user, cb) => {

    // During serialization, only the user ID is stored in the session. This helps in minimizing the session size.
    cb(null, user.id);
});

// Passport deserialization setup.
passport.deserializeUser((id, cb) => {

    // During deserialization, the user ID is used to fetch the full user information.
    db.query('SELECT * FROM users WHERE id = $1', [id], (err, result) => {

        if (err) {

            // In case of an error, it is passed to the callback.
            return cb(err);
        }

        // If no errors occur, the user object (the first row from the result) is restored to req.user, making it accessible throughout the lifecycle of the request.
        cb(null, result.rows[0]);
    });
});

// Starting the server.
app.listen(port, () => {

    // This will start the server on the specified port and log a message to the console indicating successful startup and the port number it's listening on.
    console.log(`Listening on port ${port}`);
});