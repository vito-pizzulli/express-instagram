CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    username VARCHAR(30) UNIQUE,
    name VARCHAR(50),
    bio VARCHAR(150)
);

CREATE TABLE posts (
    id SERIAL PRIMARY KEY,
    user_id INT,
    image_url VARCHAR(255) NOT NULL,
    description VARCHAR(255),
    location VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id)
);