const express = require('express');
const mysql = require('mysql2');  // ✅ Use mysql2 instead of mysql
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const os = require('os');  // ✅ Import the os module
const session = require('express-session');  // ✅ Import express-session

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'your_secret_key',  // Replace with your own secret key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }  // Set to true if using HTTPS
}));

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
        // Check if email or username already exists
        const checkUserQuery = 'SELECT * FROM users WHERE email = ? OR username = ?';
        db.query(checkUserQuery, [email, username], async (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            if (results.length > 0) {
                return res.status(400).json({ message: 'Email or username already registered' });
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert new user
            const insertUserQuery = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
            const userValues = [username, email, hashedPassword];

            db.query(insertUserQuery, userValues, (err, result) => {
                if (err) {
                    console.error('Error inserting user:', err);
                    return res.status(500).json({ message: 'Database error' });
                }

                const userID = result.insertId;

                // Insert balance into accounts table
                const insertAccountQuery = 'INSERT INTO accounts (userID, balance) VALUES (?, ?)';
                const accountValues = [userID, parseFloat(balance)];

                db.query(insertAccountQuery, accountValues, (err, result) => {
                    if (err) {
                        console.error('Error inserting account:', err);
                        return res.status(500).json({ message: 'Database error' });
                    }
                    res.json({ message: 'User registered successfully' });
                });
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
        req.session.username = username;  // Store username in session
        res.json({ message: 'Login successful' });
    });
});

// Serve send money page
app.get('/send-money-page', (req, res) => {
    if (!req.session.username) {
        return res.redirect('/login.html');  // Redirect to login if not logged in
    }
    res.sendFile(path.join(__dirname, 'public', 'send_money_page.html'));
});

// Money transfer route
app.post('/send-money', async (req, res) => {
    const { recipientUsername, password, amount } = req.body;
    const senderUsername = req.session.username;  // Get sender's username from session

    if (!senderUsername) {
        return res.status(400).json({ message: 'Sender not logged in' });
    }

    try {
        // Check if sender exists
        const checkSenderQuery = 'SELECT * FROM users WHERE username = ?';
        db.query(checkSenderQuery, [senderUsername], async (err, senderResults) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            if (senderResults.length === 0) {
                return res.status(400).json({ message: 'Invalid sender username' });
            }

            const sender = senderResults[0];

            // Compare the password with the hashed password
            const isMatch = await bcrypt.compare(password, sender.password);
            if (!isMatch) {
                return res.status(400).json({ message: 'Invalid password' });
            }

            // Check if recipient exists
            const checkRecipientQuery = 'SELECT * FROM users WHERE username = ?';
            db.query(checkRecipientQuery, [recipientUsername], (err, recipientResults) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ message: 'Database error' });
                }

                if (recipientResults.length === 0) {
                    return res.status(400).json({ message: 'Invalid recipient username' });
                }

                const recipient = recipientResults[0];

                // Check sender's balance
                const checkSenderBalanceQuery = 'SELECT * FROM accounts WHERE userID = ?';
                db.query(checkSenderBalanceQuery, [sender.id], (err, senderAccountResults) => {
                    if (err) {
                        console.error('Database error:', err);
                        return res.status(500).json({ message: 'Database error' });
                    }

                    const senderAccount = senderAccountResults[0];
                    if (senderAccount.balance < amount) {
                        return res.status(400).json({ message: 'Insufficient balance' });
                    }

                    // Deduct amount from sender's account
                    const updateSenderBalanceQuery = 'UPDATE accounts SET balance = balance - ? WHERE userID = ?';
                    db.query(updateSenderBalanceQuery, [amount, sender.id], (err, result) => {
                        if (err) {
                            console.error('Database error:', err);
                            return res.status(500).json({ message: 'Database error' });
                        }

                        // Add amount to recipient's account
                        const updateRecipientBalanceQuery = 'UPDATE accounts SET balance = balance + ? WHERE userID = ?';
                        db.query(updateRecipientBalanceQuery, [amount, recipient.id], (err, result) => {
                            if (err) {
                                console.error('Database error:', err);
                                return res.status(500).json({ message: 'Database error' });
                            }

                            // Log transaction for sender
                            const logSenderTransactionQuery = 'INSERT INTO transactions (amount, accountID) VALUES (?, ?)';
                            db.query(logSenderTransactionQuery, [-amount, sender.id], (err, result) => {
                                if (err) {
                                    console.error('Database error:', err);
                                    return res.status(500).json({ message: 'Database error' });
                                }

                                // Log transaction for recipient
                                const logRecipientTransactionQuery = 'INSERT INTO transactions (amount, accountID) VALUES (?, ?)';
                                db.query(logRecipientTransactionQuery, [amount, recipient.id], (err, result) => {
                                    if (err) {
                                        console.error('Database error:', err);
                                        return res.status(500).json({ message: 'Database error' });
                                    }

                                    res.json({ message: 'Money transferred successfully' });
                                });
                            });
                        });
                    });
                });
            });
        });
    } catch (error) {
        console.error('Error processing transfer:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Check balance route
app.post('/check-balance', async (req, res) => {
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

        // Get user's balance
        const checkBalanceQuery = 'SELECT balance FROM accounts WHERE userID = ?';
        db.query(checkBalanceQuery, [user.id], (err, balanceResults) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            const balance = balanceResults[0].balance;
            res.json({ balance });
        });
    });
});

// Route to get the logged-in username
app.get('/get-username', (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ message: 'Not logged in' });
    }
    res.json({ username: req.session.username });
});

// Function to get the local IP address
function getLocalIpAddress() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return 'localhost';
}

app.listen(port, () => {
    const ipAddress = getLocalIpAddress();
    console.log(`Server running at http://${ipAddress}:${port}/`);
    console.log(`Server running at http://localhost:${port}/signup.html`);
});