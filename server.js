const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const passport = require('passport');
const cors = require('cors');
const users = require('./routes/api/users');
const app = express();

// Passport middleware
app.use(passport.initialize());

// Passport Config
require('./config/passport')(passport);

app.use(cors());

// Body parser middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// DB Config
const db = require('./config/keys').mongoURI;

// Connect to MongoDB
mongoose
  .connect(db, { useUnifiedTopology: true, useNewUrlParser: true })
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err));

// Use Routes
app.use('/api/users', users);

const port = process.env.PORT || 8000;

app.listen(port, () => console.log(`Server running on port ${port}`));
