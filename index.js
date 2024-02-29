// const express = require('express')
// const app = express()
// const bcrypt = require('bcrypt')

// app.use(express.json())

// const users = []

// app.get('/users', (req, res) => {
//   res.json(users)
// })

// app.post('/users', async (req, res) => {
//   try { 
//     const hashedPassword = await bcrypt.hash(req.body.password, 10)
//     const user = { name: req.body.name, password: hashedPassword }
//     users.push(user)
//     res.status(201).send()
//   } catch {
//     res.status(500).send()
//   }
// })

// app.post('/users/login', async (req, res) => {
//   const user = users.find(user => user.name === req.body.name)
//   if (user == null) {
//     return res.status(400).send('Cannot find user')
//   }
//   try {
//     if(await bcrypt.compare(req.body.password, user.password)) {
//       res.send('Success')
//     } else {
//       res.send('Not Allowed')
//     }
//   } catch {
//     res.status(500).send()
//   }
// })

// app.listen(3000)

// Import required modules
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const bcrypt = require('bcrypt');

// Create MySQL connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'demo'
});

// Connect to MySQL
connection.connect();

// Initialize Express app 
const app = express(); 
app.use(bodyParser.json());

// Secret key for JWT
const secretKey = '1bc04622e669a2050d01c2495113bce0cf576975d113e20089a945bf1b508dd43093635f58a08325de7b1cfe293ddb73c4edf704bc8218523d32f8589547fd24';

// Register route
app.post('/register', (req, res) => {
  const { username, password } = req.body; 
  bcrypt.hash(password, 10, (err, hash) => { 
    if (err) {
      return res.status(500).json({ error: err });
    } else {
      const user = { username, password: hash };
      connection.query('INSERT INTO users SET ?', user, (error, results) => {
        if (error) {
          return res.status(400).json({ error });
        }
        res.status(200).json({ message: 'User registered successfully' });
      });
    }
  });
});

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  connection.query('SELECT * FROM users WHERE username = ?', [username], (error, results) => {
    if (error) {
      return res.status(400).json({ error });
    }
    if (results.length > 0) {
      const user = results[0];
      bcrypt.compare(password, user.password, (err, result) => {
        if (err || !result) {
          return res.status(401).json({ message: 'Authentication failed' });
        }
        const token = jwt.sign({ username: user.username }, secretKey, { expiresIn: '6s' });
        res.status(200).json({ token });
      });
    } else {
      res.status(401).json({ message: 'User not found' });
    }
  });
});

// Protected route example
app.get('/protected', verifyToken, (req, res) => {
  jwt.verify(req.token, secretKey, (err, authData) => {
    if (err) {
      res.sendStatus(403);
    } else {
      res.json({ message: 'Protected data accessed', authData });
    }
  });
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  console.log(bearerHeader)
  if (typeof bearerHeader !== 'undefined') {
    const bearerToken = bearerHeader.split(' ')[1];
    req.token = bearerToken;
    next();
  } else {
    res.sendStatus(403);
  }
}

// Start server
const port = 3000;
app.listen(port, () => console.log(`Server is running on port ${port}`));
