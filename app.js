require('dotenv').config();
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bodyParser = require('body-parser');
const session = require('express-session');
const helmet = require('helmet');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const CALLBACK_URL = 'http://localhost:3000/auth/callback';
const VIEW_ID = 'your_view_id';
const SESSION_SECRET = process.env.SESSION_SECRET;
const MONGODB_URL = process.env.MONGODB_URL;

// Connect to MongoDB
mongoose.connect(MONGODB_URL, { useNewUrlParser: true, useUnifiedTopology: true });

// User schema and model
const UserSchema = new mongoose.Schema({
  googleId: String,
  displayName: String,
  accessToken: String,
});
const User = mongoose.model('User', UserSchema);

const app = express();

// Middleware
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: MONGODB_URL }),
  cookie: { secure: false },
}));
app.use(passport.initialize());
app.use(passport.session());

app.set('view engine', 'ejs');

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: CALLBACK_URL,
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const existingUser = await User.findOne({ googleId: profile.id });

      if (existingUser) {
        existingUser.accessToken = accessToken;
        await existingUser.save();
        return done(null, existingUser);
      }

      const newUser = new User({
        googleId: profile.id,
        displayName: profile.displayName,
        accessToken: accessToken,
      });
      await newUser.save();
      return done(null, newUser);
    } catch (err) {
      return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/auth',
  passport.authenticate('google', {
    scope: ['https://www.googleapis.com/auth/analytics.readonly'],
    accessType: 'offline',
    prompt: 'consent',
  })
);

app.get('/auth/callback',
  async (req, res, next) => {
    passport.authenticate('google', async (err, user) => {
      try {
        if (err) {
          throw new Error('Error in Google authentication');
        }
        if (!user) {
          return res.redirect('/');
        }
        req.login(user, (loginErr) => {
          if (loginErr) {
            throw new Error('Error logging in user');
          }
          return res.redirect('/dashboard');
        });
      } catch (error) {
        next(error);
      }
    })(req, res, next);
  }
);

app.get('/dashboard', (req, res) => {
  if (!req.user) {
    res.redirect('/');
  } else {
    res.render('dashboard', { user: req.user, data: null });
  }
});

app.post('/getdata', async (req, res, next) => {
  if (!req.user) {
    res.redirect('/');
  } else {
    try {
      const { startDate, endDate, metric } = req.body;
      const analyticsData = await getAnalyticsData(req.user.accessToken, startDate, endDate, metric);
      res.render('dashboard', { user: req.user, data: analyticsData });
    } catch (error) {
      next(error);
    }
  }
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error', { error: err });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
