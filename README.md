OAuth2-JS
=========

Express-js middleware to login using Google accounts.


## Install

```sh
shell ~> npm intall --save git+https://github.com/NealRame/oauth2-js.git
```


## Example

Rename the two template files as following,

```sh
shell ~> cp test/oauth2.json.tmpl test/oauth2.json
shell ~> cp test/users.json.tmpl test/users.json
```

Then, set `test/oauth2.json` with your settings. You must provide at least:

* `client_id`,
* `client_secret`,
* `redirect_uri`

```json
{
    "client_id": "YOUR_GOOGLE_OAUTH2_CLIENT_ID",
    "client_secret": "YOUR_GOOGLE_OAUTH2_CLIENT_SECRET",
    "redirect_uri": "http://local.host/path/to/your/callback"
}
```

Then, set up your _"users databases"_, like the following:

```json
{
    "PUT_A_USER_ID_HERE": {"_id": "PUT_A_USER_ID_HERE", "initialized": false},
}
```

Finally,

```sh
shell ~> npm test
```

Go to:

* http://local.host to login.
* http://local.host/path/to/your/logout to logout.


## Setup

```javascript
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var express = require('express');
var session = require('express-session');
var OAuth2 = require('../lib/oauth2');

var app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(session({secret: 'SECRET', proxy: true, resave: true, saveUninitialized: true}));
app.use(express.static(path.join(__dirname, 'PATH_TO_YOUR_STATIC_DATA')));
```

At least the given config must be provided to the OAuth2 constructor.

```javascript
var oauth2_params = {
    client_id: "YOUR_GOOGLE_OAUTH2_CLIENT_ID",
    client_secret: "YOUR_GOOGLE_OAUTH2_CLIENT_SECRET",
    redirect_uri: "http://local.host/path/to/your/callback"
};
```

You also have to provide some helper to make the link between your _User_
_model_ and the Open ID user profile.

```javascript
var oauth2_helpers = {
    find: function(id, callback) {
        // Your implementation code here
    },
    initialized: function(user, oauth2_user_info, callback) {
        // Your implementation code here
    },
    isInitialized: function(user, callback) {
        // Your implementation code here
    },
    id: function(user) {
        // Your implementation code here
    }
};
```

Then instantiate a OAuth2 middleware object like this:

```javascript
var oauth2 = new OAuth2(oauth2_params, oauth2_helpers);

app.use(oauth2.middleware);
app.use(oauth2.route);
```

You can also listen to login events:

```javascript
oauth2.events
    .on('login-success', function(user) {
        // Your implementation code here
    })
    .on('login-failure', function(id_token) {
        // Your implementation code here
    });
```

## OAuth2 object.

#### OAuth2(params, delegates)
Construct a new `OAuth2` object given parameters to connect to the oauth2
provider and some delegate functions to map users data from the provider to
the application users data.

**Parameters:**
- `params`, _Required_.
  A hash that contains the following attributes.
  See [Google Developers Console](https://console.developers.google.com/)
  to get them.
  - `client_id`, _Required_. The client id value.
  - `client_secret`, _Required_. The client secret value.
  - `redirect_uri`, _Required_. The redirect uri value.

- `delegates`, _Required_.
  A hash object containing four functions.
  - `find(user_id, callback)`, _Required_.
    See [`find`](#finduser_id-callback) for more details.
  - `id(user)`, _Required_.
    See [`id`](#iduser) for more details.
  - `initialize`, _Required_.
    See [`initialize`](#initializeoauth2_user_info-callback)
    for more details.
  - `isInitialized`, _Required_.
    See [`isInitialized`](#is_initializeduser) for more details.

#### OAuth2#middleware
An express-js middleware. The middleware will provide locals
variables to views through the response object:
* `loggedIn`, a flag indicating if the client is logged or not;
* if the user is logged:
  - `user`, instance of _User_ _model_ matching the current session.
* if not:
  - `loginLink`, a link leading to the login page.

#### OAuth2#route
An express-js router. The router will handle two distinct endpoints:
* `PREFIX/logout`,
* `PREFIX/oauth2_callback`.

The value of `PREFIX` is determined accordingly to the value you provide
for the `redirect_uri` endpoint.
Supposing you provide `'http://test.oauth2-js.io/auth/oauth2_callback'` as
the `redirect_uri` then PREFIX will be equal to 'auth'.

#### OAuth2#events
On each succeeded or failed login, `OAuth2#events` object will emit an event.
- `login-success` on each successful connection with the user logged in as
parameter,
- `login-failure` on each failed connection with the token as parameter.

### Delegates

You have to provide four delegates when your want to construct a `OAuth2`
object. Their are used to connect your application users logic with the
oauth2 provider.
- [`find`](#finduser_id-callback)
- [`id`](#iduser)
- [`initialize`](#initializeuser-oauth2_user_info-callback)
- [`isInitialized`](#is_initializeduser-callback)

#### find(user_id, callback)
Asynchronously associate an instance of your _User_ _model_ to a given
_Open ID_
[_token_id_](http://openid.net/specs/openid-connect-core-1_0.html#IDToken).

**Parameters:**
- `user_id`,
  the value of the `sub` field of a an _Open ID token_id_.
* `callback`,
  a completion callback respecting the nodejs completion callback pattern.
  - The first argument is always reserved for an exception.
    If the operation was completed successfully, then the first argument
    will be `null` or `undefined`.
  - The second parameter is an instance of your _User_ _model_.

#### initialize(user, oauth2_user_info, callback)
Asynchronously initialize a _User_ model instance with the _Open ID_
[_UserInfo_](http://openid.net/specs/openid-connect-core-1_0.html#UserInfo).

**Parameters:**
- `user`,
  an instance of your _User_ _model_.
- `oauth2_user_info`,
  the user info data from the oauth2 provider.
- `callback`,
  a completion callback respecting the nodejs completion callbacks pattern.
  - The first argument is always reserved for an exception.
    If the operation was completed successfully, then the first
    argument will be `null` or `undefined`.
  - The third parameter is the passed instance of your _User_ _model_.

#### isInitialized(user, callback)
Asynchronously check if the given user is considered _initialized_
regarding to your _User_ _model_ state.

**Parameters:**
- `user`,
  an instance of your _User_ _model_.
- `callback`,
  a completion callback respecting the nodejs completion callback pattern.
  - The first argument is always reserved for an exception.
    If the operation was completed successfully, then the first
    argument will be `null` or `undefined`.
  - The second parameter of the callback is a boolean value, set to
    `true` if and only if the user is considered initialized.

#### id(user)
Return the id of the given user.

**Parameters:**
- `user`,
  an instance of your _User_ _model_.
