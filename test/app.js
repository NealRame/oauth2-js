var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var express = require('express');
var favicon = require('static-favicon');
var fs = require('fs');
var logger = require('morgan');
var OAuth2 = require('../lib/oauth2');
var path = require('path');
var session = require('express-session');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(favicon());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(session({secret: 'IL0veK4t', proxy: true, resave: true, saveUninitialized: true}));
app.use(express.static(path.join(__dirname, 'public')));

var users = JSON.parse(fs.readFileSync(path.join(__dirname, 'users.json')).toString());
var oauth2_params = JSON.parse(fs.readFileSync(path.join(__dirname, 'oauth2.json')).toString());

/// Define User helpers here.
var oauth2_helpers = {
    /// ### `find_user(id, callback)`
    /// Asynchronously associate an instance of your _User_ _model_ to a given
    /// _Open ID_ [_token_id_](http://openid.net/specs/openid-connect-core-1_0.html#IDToken).
    ///
    /// _Parameters_:
    /// * `token_id`,
    ///   An _Open ID token_id_. According to how you have
    ///   configured your authentication request scope parameter, this is a
    ///   possible token value:
    ///     ```javascript
    ///     id_token: {
    ///         iss: 'URL',           // REQUIRED
    ///         sub: '[0-9a-zA-Z]+',  // REQUIRED
    ///         aud: '...',           // REQUIRED
    ///         exp: 1407534254989,   // REQUIRED
    ///         iat: 1407534288627,   // REQUIRED
    ///     }
    ///     ```
    ///
    /// * `callback`,
    ///   A  completion callback respecting the nodejs completion callback
    ///   pattern.
    ///   - The first argument is always reserved for an exception.
    ///     If the operation was completed successfully, then the first
    ///     argument will be `null` or `undefined`.
    ///   - The second parameter is an instance of your _User_ _model_
    find_user: function(id, callback) {
        callback(null, users[id]);
    },
    /// ### `is_initialized(user)`
    /// Unsynchronously check if the given user is considered _initialized_
    /// regarding to your _User_ _model_ state.
    ///
    /// _Parameters_:
    /// * `user`,
    ///   An instance of your _User_ _model_.
    ///
    /// * `callback`,
    ///   A  completion callback respecting the nodejs completion callback
    ///   pattern.
    ///   - The first argument is always reserved for an exception.
    ///     If the operation was completed successfully, then the first
    ///     argument will be `null` or `undefined`.
    ///   - The second parameter of the callback is a boolean value, set to
    ///     `true` if and only if the user is considered initialized.
    is_initialized: function(user, callback) {
        callback(null, user.initialized);
    },
    /// ### `map_oauth2_user_info(oauth2_user_info, callback)`
    /// Unsynchronously map the _ Open ID_ [_UserInfo_](http://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
    /// attributes on the given instance of your _User_ _model_.
    ///
    /// _Parameters_:
    /// * `params`
    ///   A hash object containing the following attributes:
    ///   - **`token`**, see `find_user()` above for more details,
    ///   - `user`, an instance of your _User_ _model_.
    ///
    /// * `oauth2_user_info`
    ///   A _UserInfo_ object.
    ///
    /// * `callback`
    ///   A  completion callback respecting the nodejs completion callbacks
    ///   pattern.
    ///   - The first argument is always reserved for an exception.
    ///     If the operation was completed successfully, then the first
    ///     argument will be `null` or `undefined`.
    ///   - The third parameter is the passed instance of your _User_ _model_.
    map_oauth2_user_info: function(user, oauth2_user_info, callback) {
        console.log(user);
        console.log(oauth2_user_info);
        user.name = {
            first: oauth2_user_info.given_name,
            last: oauth2_user_info.family_name
        };
        user.email = oauth2_user_info.email;
        user.picture = oauth2_user_info.picture;

        callback(null, user);
    }
};

var oauth2 = new OAuth2(oauth2_params, oauth2_helpers);

app.use(oauth2.middleware());
app.use(oauth2.route());
app.use('/', require('./routes/index'));

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});

module.exports = app;
