import express from 'express';
import { config } from 'dotenv';
config();
import bodyParser from 'body-parser';
import { hash, compare } from 'bcrypt';
import path, { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} from
  '@simplewebauthn/server';
import base64url from 'base64url';
import { signin, signup } from './db/db.mjs';
import { Strategy as GitHubStrategy } from 'passport-github'; 
import DiscordStrategy from 'passport-discord'; 
import passport from 'passport';
import session from 'express-session';
const authenticators = {};
const app = express();
const { urlencoded } = bodyParser;
import querystring from 'querystring';
import secret from './client_secret.json' assert { type: 'json' }; //added
import { profile } from 'console'; //
const __dirname = dirname(fileURLToPath(import.meta.url));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(urlencoded({ extended: true }));
app.use(express.static(join(__dirname, 'public')));

// WebAuthn configuration
const rpID = 'localhost';
const expectedOrigin = 'http://localhost:3000';
// Endpoint to start the registration process
app.post('/register/start', async (req, res) => {
  // Extract username from request body
  const { username } = req.body;
  if (!username) {
    return res.status(400).send({ error: 'Username is required' });
  }
  // Check if user already exists
  const user = await signin(username);
  if (user) {
    return res.status(400).send({ error: 'User already exists' });
  }
  // Generate registration options
  const registrationOptions = await generateRegistrationOptions({
    rpName: 'Future Of Authentication',
    rpID,
    userID: base64url(Buffer.from(username)),
    userName: username,
    timeout: 60000, // Timeout for the request in milliseconds
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'discouraged',
    },
    supportedAlgorithmIDs: [-7, -257],
  });
  // Store the challenge temporarily for verification in the next step
  authenticators[username] = {
    challenge: registrationOptions.challenge,
  };
  // Send registration options to the client
  return res.send(registrationOptions);
});
// Endpoint to finish the registration process
app.post('/register/finish', async (req, res) => {
  const { username, attestationResponse } = req.body;
  // Retrieve the stored challenge from the 'authenticators' object
  const expectedChallenge = authenticators[username].challenge;
  let verification;
  try {
    // Verify the registration response
    verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }
  // Check if verification was successful
  const { verified } = verification;
  if (verified) {
    // Prepare user data for storage
    const user = {
      devices: [{
        credentialPublicKey:
          base64url.encode(verification.registrationInfo.credentialPublicKey),
        credentialID:
          base64url.encode(verification.registrationInfo.credentialID),
        transports: attestationResponse.response.transports,
      }],
      userID: base64url(Buffer.from(username)),
      userName: username,
    };
    // Remove the temporary authenticator
    authenticators[username] = undefined;
    try {
      // Store the user in the database
      await signup(username, user);
    }
    catch (error) {
      return res.status(400).send({ error: error.message });
    }
    // Send verification result to the client
    return res.send({ verified });
  } else {
    return res.status(400).send({
      error: 'Unable to verify registration'
    });
  }
});
// Endpoint to start the login process
app.post('/login/start', async (req, res) => {
  const { username } = req.body;
  // Verify if the user exists
  const user = await signin(username);
  if (!user) {
    return res.status(400).send({ error: 'User does not exist' });
  }
  // Generate authentication options
  const options = {
    rpID,
    timeout: 60000, // Timeout for the request in milliseconds
    userVerification: 'required',
    allowCredentials: user.devices.map((device) => ({
      id: new Uint8Array(base64url.toBuffer(device.credentialID)),
      type: 'public-key',
      transports: device.transports,
    })),
  };
  const authenticationOptions = await generateAuthenticationOptions(options);
  // Store the challenge for later use during verification
  authenticators[username] = {
    currentChallenge: authenticationOptions.challenge,
  };
  // Send authentication options to the client
  return res.send(authenticationOptions);
});
// Endpoint to finish the login process
app.post('/login/finish', async (req, res) => {
  const { username, assertionResponse } = req.body;
  const expectedChallenge = authenticators[username].currentChallenge;
  const user = await signin(username);
  const device = user.devices[0];
  let verification;
  try {
    // Verify the authentication response
    verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: new
          Uint8Array(base64url.toBuffer(device.credentialID)),
        credentialPublicKey: new
          Uint8Array(base64url.toBuffer(device.credentialPublicKey)),
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }
  // Send the verification result to the client
  const { verified } = verification;
  if (verified) {
    return res.send({ verified });
  } else {
    return res.status(400).send({ error: 'Unable to verify login' });
  }
});

// Registration endpoint
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await hash(password, 10);
    const user = { username, password: hashedPassword };
    signup(username, user);
    res.send('User registered successfully');
  } catch (error) {
    res.status(500).send('Error registering new user');
  }
});
app.use(session({
  secret: process.env.GITHUB_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, //cookie will be stored only in the server not the browser
    secure: false,
    maxAge: 24 * 60 * 60 * 1000, //how long the session is

  },
})
);
app.use(passport.initialize());
app.use(passport.session());
//creat a session
passport.serializeUser(function (user, cb) {
  cb(null, user.id);
});
passport.deserializeUser(function (id, cb) {
  cb(null, id);
});

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_ID,
  clientSecret: process.env.GITHUB_SECRET,
  callbackURL: 'http://localhost:3000/auth/github/callback'
},
  function (accessToken, refreshToken, profile, cb) { //profile is ur info if u login successfully
    console.log(profile);
    cb(null, profile);

  }
));

//auth

app.get('/auth/github', passport.authenticate('github'));
app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/failure' }),

  function (req, res) {
    // Successful authentication
    res.send(`
      <h1>Login successful</h1>
      <p>Welcome ${req.user.username}</p>
    `);
  }
);
//DISCORD
//we won't creat a session in discord as github
passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_ID,
  clientSecret: process.env.DISCORD_SECRET,
  callbackURL: 'http://localhost:3000/auth/discord/callback',
  scope: ['identify', 'email']
}, (accessToken, refreshToken, profile, cb) => {
  console.log(profile);
  cb(null, profile);
}));
// Authentication routes
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', passport.authenticate('discord', { failureRedirect: '/failure' }), (req, res) => {
  // Successful authentication
  res.send(`
    <h1>Login successful</h1>
    <p>Welcome ${req.user.username}</p>
    <p>Email: ${req.user.email}</p>

  `);
});


// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  let user = signin(username);
  if (!user) {
    return res.status(400).send('Invalid credentials');
  }
  const match = await compare(password, user.password);
  if (match) {
    res.send('Login successful');
  } else {
    res.status(400).send('Invalid credentials');
  }
});

//first step get the authorization code from google 
const CLIENT_ID = secret.client_id//added
const CLIENT_SECRET = secret.client_secret//added
const REDIRECT_URI = 'http://localhost:3000/auth/google/callback'; //from slide that i put in google too

app.get('/auth/google', (req, res) => {
  const authorizationUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
  const params = {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email', // Updated scope to only take email
    access_type: 'online'
  };
  res.redirect(`${authorizationUrl}?${querystring.stringify(params)}`);
});
//end of the first step we got the authorization code

// exchanging the authorization code and then using it to get the access token
// and then using the access token to get the user's email address
app.get('/auth/google/callback', async (req, res) => {
  const code = req.query.code; //authorization code
  if (!code) {
    return res.status(400).send('Authorization code is missing');
  }
  try {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: querystring.stringify({
        code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    if (!tokenResponse.ok) {
      throw new Error('Failed to exchange authorization code for access token');
    }

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    if (!accessToken) {
      throw new Error('Access token is missing in the response');
    }

    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v1/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!userInfoResponse.ok) {
      throw new Error('Failed to fetch user info');
    }

    const userData = await userInfoResponse.json();
    // send Login successful

    res.send(`
      <h1>Login successful</h1>
      <p>Welcome ${userData.email}</p>
  `);

  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

//end of step two

app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login')
}
app.get('/favicon.ico', (req, res) => res.status(204));