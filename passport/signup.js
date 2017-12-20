var LocalStrategy = require('passport-local').Strategy;
var User = require('../models/user');
var bCrypt = require('bcrypt-nodejs');

module.exports = function(passport) {
    passport.use('signup', new LocalStrategy(
	{
	    passReqToCallback : true // allows us to pass back the req to the callback
	},
	function(req, username, password, done) {
	    findOrCreateUser = function() {
		// find a user with provided username
		User.findOne({ 'username' : username }, function(err, user) {
		    if(err) {
			console.log('Error in Signup: ' + err);
			return done(err);
		    }
		    // user exists
		    if (user) {
			console.log('User already exists with username : ' + user);
			return done(null, false, req.flash('message', 'User Already Exists'));
		    } else {
			// if no user present with that email
			// create user
			var newUser = new User();

			// set the user's local credentials
			newUser.username = username;
			newUser.password = createHash(password);
			newUser.email = req.param('email');
			newUser.firstName = req.param('firstName');
			newUser.lastName = req.param('lastName');

			console.log('New User: ' + newUser);
			console.log('Request: ' + req);
			
			// save the user
			newUser.save(function(err) {
			    if (err) {
				console.log('Error in Saving user: ' + err);
				throw err;
			    }
			    console.log('User Registration Successful');
			    return done(null, newUser);
			});
		    }
		});
	    };

	    // Delay the execution of findOrCreateUser and execute the method
	    // in the next ticket of the event loop
	    process.nextTick(findOrCreateUser);
	})
		);

    // Generates hash using bCrpyt
    var createHash = function(password) {
	return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
    }
}
    
