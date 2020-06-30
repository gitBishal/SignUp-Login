const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const keys = require('../../config/keys');
const passport = require('passport');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Load Input Validation
const validateRegisterInput = require('../../validation/register');
const validateLoginInput = require('../../validation/login');

// Load User model
const User = require('../../models/User');
const Token = require('../../models/EmailToken');

// @route   GET api/users/confirmation
// @desc    Token confirmation and user registration
// @access  Public
router.get('/confirmation/:token', (req, res) => {
  console.log(req.body);
  var errors = {};

  Token.findOne({ token: req.params.token }).then(token => {
    if (!token) {
      errors.tokenNotFound =
        'We were unable to find a valid token. Your token my have expired.';
      return res.status(400).josn({ errors });
    }

    // If we found a token, find a matching user
    User.findOne({ _id: token.user }).then(user => {
      if (!user)
        return res
          .status(400)
          .json({ msg: 'We were unable to find a user for this token.' });
      if (user.isVerified)
        return res.status(400).json({
          type: 'already-verified',
          msg: 'This user has already been verified.',
        });

      // Verify and save the user
      const userFields = {};
      userFields.isVerified = true;
      User.findOneAndUpdate(
        { _id: token.user },
        { $set: userFields },
        { new: true }
      )
        .then(user =>
          res
            .status(200)
            .json({ msg: 'The account has been verified. Please log in.' })
        )
        .catch(err => console.log(err));
    });
  });
});

// @route   GET api/users/confirmation
// @desc    Resend token
// @access  Public

router.post('/resend', (req, res) => {
  const { errors, isValid } = validateLoginInput(req.body);

  // Check Validation
  if (!isValid) {
    return res.status(400).json(errors);
  }
  User.findOne({ email: req.body.email }).then(user => {
    if (!user) {
      errors.userNotFound = 'There is no user with this email';
      return res.status(400).json(errors);
    } else {
      if (user.isVerified) {
        errors.userAlreadyVerified = 'This email has already been verified';
        return res.status(400).json(errors);
      }

      //Create a verification token save it and then email it to the given address
      var token = new Token({
        user: user.id,
        token: crypto.randomBytes(16).toString('hex'),
      });
      // Save the verification token
      token
        .save()
        .then(token => {
          //Send the email
          var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
              user: 'Your email id ', //Store it in env variable
              pass: 'password for your email',
            },
          });
          var mailOptions = {
            from: 'mailsenderId',
            to: user.email,
            subject: 'Account Verification Token',
            text:
              'Hello,\n\n' +
              'Please verify your account by clicking the link: \nhttp://' +
              req.headers.host +
              '/api/users/confirmation/' +
              token.token +
              '.\n',
          };
          transporter.sendMail(mailOptions, function (err) {
            if (err) {
              errors.sendingFailed = 'Email sending failed';
              console.log(err);
              return res.status(400).json(errors);
            }

            res.status(200).json({
              msg: 'A verification email has been sent to ' + user.email + '.',
            });
          });
        })
        .catch(err => console.log(err));
    }
  });
});

// @route   POST api/users/register
// @desc    Register user
// @access  Public
router.post('/register', (req, res) => {
  const { errors, isValid } = validateRegisterInput(req.body);

  // Check Validation
  if (!isValid) {
    return res.status(400).json(errors);
  }

  User.findOne({ email: req.body.email }).then(user => {
    if (user) {
      errors.email = 'Email already exists';
      return res.status(400).json(errors);
    } else {
      const newUser = new User({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
      });

      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;
          newUser
            .save()
            .then(user => {
              // Create a verification token for this user
              var token = new Token({
                user: user.id,
                token: crypto.randomBytes(16).toString('hex'),
              });
              // Save the verification token
              token
                .save()
                .then(token => {
                  //Send the email
                  var transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                      user: 'Your email id ',
                      pass: 'Your email password',
                    },
                  });
                  var mailOptions = {
                    from: 'your email id',
                    to: user.email,
                    subject: 'Account Verification Token',
                    text:
                      'Hello,\n\n' +
                      'Please verify your account by clicking the link: \nhttp://' +
                      req.headers.host +
                      '/api/users/confirmation/' +
                      token.token +
                      '.\n',
                  };
                  transporter.sendMail(mailOptions, function (err) {
                    if (err) {
                      errors.sendingFailed = 'Email sending failed';
                      console.log(err);
                      return res.status(400).json(errors);
                    }

                    res.status(200).json({
                      msg:
                        'A verification email has been sent to ' +
                        user.email +
                        '.',
                    });
                  });
                })
                .catch(err => console.log(err));
            })
            .catch(err => console.log(err));
        });
      });
    }
  });
});

// @route   GET api/users/login
// @desc    Login User / Returning JWT Token
// @access  Public
router.post('/login', (req, res) => {
  const { errors, isValid } = validateLoginInput(req.body);

  // Check Validation
  if (!isValid) {
    return res.status(400).json(errors);
  }

  const email = req.body.email;
  const password = req.body.password;

  // Find user by email
  User.findOne({ email }).then(user => {
    // Check for user
    if (!user) {
      errors.email = 'User not found';
      return res.status(404).json(errors);
    }

    // Check Password
    bcrypt.compare(password, user.password).then(isMatch => {
      if (isMatch) {
        // User Matched
        // Make sure the user has been verified
        if (!user.isVerified) {
          errors.emailNotVerified = 'Your account has not been verified.';
          res.status(400).json(errors);
        }

        const payload = {
          id: user.id,
          name: user.name,
          role: user.role,
        }; // Create JWT Payload

        // Sign Token
        jwt.sign(
          payload,
          keys.secretOrKey,
          { expiresIn: 3600 },
          (err, token) => {
            res.json({
              success: true,
              token: 'Bearer ' + token,
            });
          }
        );
      } else {
        errors.password = 'Password incorrect';
        return res.status(400).json(errors);
      }
    });
  });
});

// @route   GET api/users/current
// @desc    Return current user
// @access  Private
router.get(
  '/current',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    res.json({
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
    });
  }
);

module.exports = router;
