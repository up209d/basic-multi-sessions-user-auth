const express = require('express');
const session = require('express-session');
const expressJwt = require('express-jwt');
const jwt = require('jsonwebtoken');

// Initialize Express Server
const app = express();
const serverStorage = require('./server.storage');
const secret = serverStorage.secret;
console.log('Secret key: ', secret);

const globalMaxAge = 1000 * 5; // * 60 * 24 * 1; // 1 day

// Start a session with client
app.use(session({
	secret: secret,
	maxAge: globalMaxAge,
	cookie: {
		// secure: true, // Secure only work with HTTPS though it is recommended but we just disable it for now
		maxAge: globalMaxAge
	},
	resave: false, // Read github.com/expressjs/session
	saveUninitialized: false, // if true, it will save session info if session info haven't been changed/initialized
	// When session is saved, force maxAge countdown to be reset (also it won't do with uninitialize session as saveUninitialized is set to false)
	// It will be useful in order to sync JWT expires with our session expires
	rolling: true
}));
app.use(express.json()); // request as json object
app.use(express.urlencoded({
	extended: false
})); // body-parser options

// Request for authentication token, only accept POST request
app.post('/auth', function (req, res) {
	// Database check (bcrypt user/password matching)
	let user = serverStorage.checkAuthentication(req.body.user, req.body.pwd);
	if (user) {
		// Assign user to current session (later we can compare with token user)
		// This also save the session automatically (Or we can use req.session.save())
		// then reset the maxAge of current Session and Cookie to keep in sync with next comming jwt
		// By option rolling: true, each time the session is saved, its maxAge will be reset
		req.session.users = Object.assign({}, req.session.users, {
			[req.body.user]: {
				// username | user email as id
				id: req.body.user,
				// ip address as client address
				address: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
				// client user agent for further checking
				agent: req.headers['user-agent']
			}
		});

		// Add session to user database
		serverStorage.addSessionToUser(
			req.body.user,
			req.session,
			globalMaxAge,
			function (user, session) {
				console.log(user + ' with ' + session + ' session has been expried!!!');
			}
		);

		// Generate a token with user information (payload)
		let token = jwt.sign({
			name: user.name,
			session: req.session.id
		}, secret, {
			algorithm: 'HS256',
			expiresIn: globalMaxAge + 'ms',
			notBefore: '1s'
		});

		// Send token out as a response
		return res.status(200).json({
			message: res.statusCode + ': You passed!!!',
			session: req.session.id,
			token
		});
	}
	// Otherwise, send failed message
	return res.status(401).json({
		message: res.statusCode + ': Incorrect user/password!!!',
		session: req.session.id
	})
});

// Check for authentication
app.use(
	'/check',
	// Pass through expressJwt middleware for doing jwt.verify with the token in req.headers.authorization
	// also inject user with contain payload from jwt token to req
	expressJwt({
		secret: secret
	}),
	// If the expressJwt return error, treat it here
	function (err, req, res, next) {
		if (err) {
			// console.log(err)
			return res.status(401).json({
				message: err.status + ': You have failed, invalid token!!!',
				session: req.session.id
			});
		} else {
			// If no error, next() to next middleware
			return next();
		}
	},
	// If the token is verified, continue checked with the session record on server
	function (req, res) {
		// Check whether req.session.user is matched with token user (req.user)
		if (
			// jwt session check
			req.session.id === req.user.session &&
			// session store check
			!!req.session.users &&
			!!req.session.users[req.user.name] &&
			// database check whether session is attached to user
			!!serverStorage.isSessionRegistered(req.user.name, req.session.id)
		) {
			res.status(200).json({
				message: res.statusCode + ': You have passed!!!',
				name: req.session.user,
				session: req.session.id
			});
		} else {
			res.status(401).json({
				message: res.statusCode + ': You have failed, token is not matched with current session!!!',
				session: req.session.id
			});
		}
	}
);

// [DEBUG] Log session
app.use('/session', function (req, res) {
	req.sessionStore.all(function (err, sessions) {
		console.log(sessions)
	});
	return res.status(200).json({
		session: req.session.id,
		id: req.sessionID
	})
});

// [DEBUG] Log database
app.use('/database', function (req, res) {
	console.log(serverStorage.users);
	return res.status(200).json({
		session: req.session.id,
		id: req.sessionID
	})
});

// Start Server
app.listen(20987, function (err) {
	if (err) {
		console.log(err);
		return err;
	}
	console.log('----------------------------------------------------------');
	console.log();
	console.log('\x1b[36m', 'Server Started at Port: ', 'http://localhost:' + 20987);
	console.log('\x1b[30m');
	console.log('----------------------------------------------------------');
	console.log('You can now play around with requesting client (Postman)');
});