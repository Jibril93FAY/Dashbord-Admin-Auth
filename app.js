const express = require('express');
const path = require('path');
const fs = require('fs');
const ejs = require('ejs');
const bcrypt = require('bcryptjs');
const Jwt = require('jsonwebtoken');
require('dotenv').config();
const sqlite3 = require('sqlite3').verbose();

const app = express();

app.engine("html", ejs.__express);
app.set("view engine", "html");
app.set("views", path.join(__dirname, "views"));

app.use(express.json());

const db = new sqlite3.Database('./database.db');

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT
)`);  

app.get('/', (req, res) => {
  res.render('index', { title: 'Home' });
});

app.get('/register/', (req, res) => {
  res.render('register', { title: 'Register' });
});

app.get('/login/', (req, res) => {
  res.render('login', { title: 'Login' });
});

app.get('/about/', (req, res) => {
  res.render('about', { title: 'About' });
});

app.get('/services/', (req, res) => {
  res.render('services', { title: 'Services' });
});

app.get('/contact/', (req, res) => {
  res.render('contact', { title: 'Contact' });
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
   
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `INSERT INTO users (email, password) VALUES (?, ?)`;
    db.run(query, [email, hashedPassword], function(err) {
      if (err) {
        return res.status(400).json({ message: 'Email already exists', error: err.message });
      }
      res.status(201).json({ message: 'User created successfully' }); 
    });
  });

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const query = `SELECT * FROM users WHERE email = ?`;
  db.get(query, [email], async (err, user) => {
    if (err || !user) {
      return res.status(400).json({ error : 'Authentication failed' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error : 'Authentication failed' });
    } 
    const token = Jwt.sign({id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES });
    res.status(200).json({message:"Connection successful", token });
  });
});

function authmiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = Jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}


app.get('/dashboard', authmiddleware, (req, res) => {
 res.status(200).json({ message: 'Welcome to the dashboard!', user: req.user  });
});

module.exports = app;