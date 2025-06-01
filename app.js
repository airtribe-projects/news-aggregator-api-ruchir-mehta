const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const axios = require('axios');

require('dotenv').config();


const app = express();
const port = 3000;

const JWT_SECRET = process.env.JWT_SECRET;
const GNEWS_API_KEY = process.env.GNEWS_API_KEY;

if (!JWT_SECRET) {
    console.error('JWT_SECRET is not defined in the environment variables');
    process.exit(1);
}

if (!GNEWS_API_KEY) {
    console.error('GNEWS_API_KEY is not defined in the environment variables');
    process.exit(1);
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const users = [];

app.listen(port, (err) => {
    if (err) {
        return console.log('Something bad happened', err);
    }
    console.log(`Server is listening on http://localhost:${port}`);
});


function authenticationToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send({ error: 'Authorization header is missing or invalid. Expected syntax Bearer <token>' });
    }
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ error: 'Invalid token' });
        }
        req.user = decoded;
        next();
    });
};

app.get('/', (req, res) => {
    res.send('Welcome to the News Aggregator API!');
});

app.post('/login', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        const { username, password } = req.body;
        const user = users.find(user => user.username === username);
        if (!user || !bcrypt.compareSync(password, user.hashedPassword)) {
            return res.status(401).send({ error: 'Invalid username or password' });
        }
        // If the request does not have Basic Auth, we can still allow login with username and password
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '10m' });
        return res.send({ token: `Bearer: ${token}` });
        // return res.status(401).send({ error: 'Authorization header is missing or invalid. Expected syntax Basic <auth_token>' });
    }
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ error: 'Invalid token' });
        }
        const user = users.find(user => user.username === decoded.username);
        if (!user) {
            return res.status(401).send({ error: 'User not found' });
        }
        res.send({ message: 'Login successful', user: { username: user.username } });
    });
});

app.get('/users', authenticationToken, (req, res) => {
    // Protect this route with authentication
    if (!req.user) {
        return res.status(401).send({ error: 'Unauthorized' });
    }
    // Return a list of users, but only the username
    res.send(users.map(user => ({ username: user.username })));
    
});

app.get('/preferences', authenticationToken, (req, res) => {
    // This is a placeholder for user preferences
    // In a real application, you would fetch user preferences from a database
    if (!req.user) {
        return res.status(401).send({ error: 'Unauthorized' });
    }
    const foundUser = users.find(user => user.username === req.user.username);
    if (!foundUser) {
        return res.status(404).send({ error: 'User not found' });
    }
    // Return user preferences
    // For simplicity, we will just return the username
    res.send({ message: 'User preferences', preferences: foundUser.preferences || {}, username: foundUser.username });
});

app.put('/preferences', authenticationToken, (req, res) => {
    // This is a placeholder for updating user preferences
    // In a real application, you would update user preferences in a database
    if (!req.user) {
        return res.status(401).send({ error: 'Unauthorized' });
    }
    const foundUser = users.find(user => user.username === req.user.username);
    if (!foundUser) {
        return res.status(404).send({ error: 'User not found' });
    }
    const { preferences } = req.body;
    if (!preferences || typeof preferences !== 'object') {
        return res.status(400).send({ error: 'Preferences must be an object' });
    }
    foundUser.preferences = preferences;
    
    res.send({ message: 'Preferences updated successfully', preferences, username: foundUser.username });
});

app.post('/users/signup', (req, res) => {
    const { username, password, preferences } = req.body;
    // Here you would typically save the user to your database. For now emulate it in memory
    if (!username || !password || !preferences) {
        return res.status(400).send({ error: 'Username, password and preferences are required. Preferences must be an object accepting keys land, max or country' });
    }

    if (users.find(user => user.username === username)) {
        return res.status(400).send({ error: 'Username already exists' });
    }
    const hashedPassword = bcrypt.hashSync(password, 10);
    const user = {
        username,
        hashedPassword,
        preferences: preferences || {}
    };
    users.push(user);
    res.status(200).send({ message: 'User registered successfully', user: { username: user.username, preferences: user.preferences } });
});

app.get('/news', authenticationToken, (req, res) => {
    // This is a placeholder for fetching news articles

    if (!req.user) {
        return res.status(401).send({ error: 'Unauthorized' });
    }

    const foundUser = users.find(user => user.username === req.user.username);
    if (!foundUser) {
        return res.status(404).send({ error: 'User not found' });
    }

    const {q} = req.query;
    if (!q) {
        return res.status(400).send({ error: 'Query parameter "q" is required' });
    }

    // For simplicity, we will just return a static list of articles
    const articles = [];

    let url = `https://gnews.io/api/v4/search?q=${q}&apikey=${GNEWS_API_KEY}`;

    if (foundUser.preferences.lang) {
        url += `&lang=${foundUser.preferences.lang}`;
    }
    if (foundUser.preferences.max) {
        url += `&max=${foundUser.preferences.max}`;
    }
    if (foundUser.preferences.country) {
        url += `&country=${foundUser.preferences.country}`;
    }
    axios.get(url)
        .then(response => {
            if (response.data && response.data.articles) {
                res.status(200).send({
                    message: 'News articles fetched successfully',
                    news: response.data.articles,
                    user: {
                        username: foundUser.username,
                        preferences: foundUser.preferences
                    }
                });
            }
        })
        .catch(error => {
            console.error('Error fetching news:', error);
            return res.status(500).send({ error: 'Failed to fetch news articles' });
        });
    
});

module.exports = app;