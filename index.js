const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const process = require('process');
const bcrypt = require('bcrypt');
const uuid = require('uuid');
const con = require('./db');

const app = express();
const cwd = process.cwd();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const cookieParser = require('cookie-parser');
const session = require('express-session');

app.use(cookieParser());
app.use(
  session({
    secret: '143',
    resave: false,
    saveUninitialized: true,
  })
);
app.get('/', (req, res) => {

    res.redirect('/loginpage');

  
});

app.get('/home', (req, res) => {
  let csrf = uuid.v1();
  req.session.token = { csrf };
  res.cookie('secret', csrf);
  res.sendFile(path.join(cwd, '/index.html'));
});

app.get('/loginpage', (req, res) => {
  res.sendFile(path.join(cwd, '/login.html'));
});

app.post('/login', (req, res) => {
  let email = req.body.email;
  let pass = req.body.password;
  let sql = 'SELECT * FROM users WHERE email = ?';

  con.query(sql, [email], (err, result, fields) => {
    if (err) {
      console.error(err);
      res.redirect('/loginpage?error=error');
    } else {
      if (result.length > 0) {
        const storedPassword = result[0].password;
        bcrypt.compare(pass, storedPassword, (err, passwordMatch) => {
          if (err) {
            console.error(err);
            res.redirect('/loginpage?error=error');
          } else if (passwordMatch) {
            res.end('Login successfully');
          } else {
            res.redirect('/loginpage?error=invalid');
          }
        });
      } else {
        res.redirect('/loginpage?error=invalid');
      }
    }
  });
});


app.post('/register', (req, res) => {
  let uname = req.body.name;
  let pass = req.body.password;
  let email = req.body.email;
  let csrf = req.session.token.csrf;
  console.log(csrf);

if(req.session.token.csrf == req.cookies.secret){
  bcrypt.hash(pass, 10, function (err, hash) {
    sql =
      'INSERT INTO users (`id`, `uname`, `email`, `password`) VALUES (NULL, ?, ?, ?)';
    params = [uname, email, hash];
    con.query(sql, params, (err, result, field) => {
      if (err == undefined) {
        res.redirect('/loginpage');
      } else {
        res.end('Something went wrong');
      }
    });
  });
}else{
  res.redirect('/home')
}
});

app.listen(2000, () => {
  console.log('Server started on port 2000');
});
