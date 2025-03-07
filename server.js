const express = require('express');
const mysql = require('mysql2');  // ✅ Use mysql2 instead of mysql
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// MySQL connection using mysql2
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Rishi@2005',
    database: 'banking'
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.stack);
        return;
    }
    console.log('Connected to database');
});

// Sign-up route
app.post('/signup', async (req, res) => {
    const { username, email, balance, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    try {
        // Check if email already exists
        const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
        db.query(checkEmailQuery, [email], async (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            if (results.length > 0) {
                return res.status(400).json({ message: 'Email already registered' });
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert new user
            const insertQuery = 'INSERT INTO users (username, email, balance, password) VALUES (?, ?, ?, ?)';
            const values = [username, email, parseFloat(balance), hashedPassword];

            db.query(insertQuery, values, (err, result) => {
                if (err) {
                    console.error('Error inserting user:', err);
                    return res.status(500).json({ message: 'Database error' });
                }
                res.json({ message: 'User registered successfully' });
            });
        });

    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Check if user exists
    const checkUserQuery = 'SELECT * FROM users WHERE username = ?';
    db.query(checkUserQuery, [username], async (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        const user = results[0];

        // Compare the password with the hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        // Authentication successful
        res.json({ message: 'Login successful' });
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`Signup page: http://localhost:${port}/signup.html`);  // ✅ Prints signup page URL
});
