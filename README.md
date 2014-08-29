OAuth2-JS
=========

Express-js middleware to login using Google accounts.


---
Install
-------

```sh
shell ~> npm intall --save git+https://github.com/NealRame/oauth2-js.git
```


---
Example
-------

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

Got to:

* http://local.host/path/to/your/login to login.
* http://local.host/path/to/your/logout to logout.


---
Setup
-----

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
    find_user: function(token, callback) {
        // Your implementation code here
    },
    is_initialized: function(params, callback) {
        // Your implementation code here
    },
    map_oauth2_user_info: function(params, oauth2_user_info, callback) {
        // Your implementation code here
    }
};
```

Then instanciate a OAuth2 middleware object like this:

```javascript
var oauth2 = new OAuth2(oauth2_params, oauth2_helpers);

app.use(oauth2.middleware());
app.use(oauth2.route());
```


---
`OAuth2` Object.
----------------



`OAuth2` Object.
----------------


### Constructor

_Parameters_:

* `params`, _Required_.

  A hash that contains the following attributes.
  See [Google Developers Console](https://console.developers.google.com/)
  to get them.

  - `client_id`, _Required_.
    The client id value.

  - `client_secret`, _Required_.
    The client secret value.

  - `redirect_uri`, _Required_.
    The redirect uri value.

* `helpers`, _Required_.

  A hash object containing three functions helpers.

  - `find_user`, _Required_.
    See [`find_user`](#find_userid-callback) for more details.

  - `is_initialized`, _Required_.
    See [`is_initialized`](#is_initializeduser) for more details.

  - `map_user`, _Required_.
    See [`map_user`](#map_oauth2_user_infooauth2_user_info-callback)
    for more details.


### Methods

#### `middleware()`
Returns an express-js middleware. The middleware will provide locals
variables to views througth the response object:
* `loggedIn`, a flag indicating if the client is logged or not;
* if the user is logged:
  - `user`, instance of _User_ _model_ matching the current session.
* if not:
  - `loginLink`, a link leading to the login page.

#### `route()`
Returns an express-js router. The router will handle two distinct
endpoints:

* `PREFIX/logout`,
* `PREFIX/oauth2_callback`.

The value of `PREFIX` is determined accordingly to the value you provide
for the `redirect_uri` endpoint.
Supposing you provide `'http://test.oauth2-js.io/auth/oauth2_callback'` as
the `redirect_uri` then PREFIX will be equal to 'auth'.


### Helpers

You have to provide three helpers when your want to construct a `OAuth2`
object:
* [`find_user`](#find_userid-callback),
* [`is_initialized`](#is_initializeduser),
* [`map_user`](#map_oauth2_user_infooauth2_user_info-callback).

#### `find_user(id, callback)`
Asynchronously associate an instance of your _User_ _model_ to a given
_Open ID_
[_token_id_](http://openid.net/specs/openid-connect-core-1_0.html#IDToken).

_Parameters_:
* `token_id`,
  An _Open ID token_id_. According to how you have
  configured your authentication request scope parameter, this is a
  possible token value:
    ```javascript
    id_token: {
        iss: 'URL',
        sub: '[0-9a-zA-Z]+',
        aud: '...',
        exp: 1407534254989,
        iat: 1407534288627
    }
    ```

* `callback`,
  A  completion callback respecting the nodejs completion callback
  pattern.
  - The first argument is always reserved for an exception.
    If the operation was completed successfully, then the first
    argument will be `null` or `undefined`.
  - The second parameter is an instance of your _User_ _model_

#### `is_initialized(user)`
Asynchronously check if the given user is considered _initialized_
regarding to your _User_ _model_ state.

_Parameters_:
* `user`,
  An instance of your _User_ _model_.

* `callback`,
  A  completion callback respecting the nodejs completion callback
  pattern.
  - The first argument is always reserved for an exception.
    If the operation was completed successfully, then the first
    argument will be `null` or `undefined`.
  - The second parameter of the callback is a boolean value, set to
    `true` if and only if the user is considered initialized.

#### `map_user(oauth2_user_info, callback)`
Asynchronously map the _ Open ID_
[_UserInfo_](http://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
attributes on the given instance of your _User_ _model_.

_Parameters_:
* `params`
  A hash object containing the following attributes:
  - `token`, see `find_user()` above for more details,
  - `user`, an instance of your _User_ _model_.

* `oauth2_user_info`
  A _UserInfo_ object.

* `callback`
  A  completion callback respecting the nodejs completion callbacks
  pattern.
  - The first argument is always reserved for an exception.
    If the operation was completed successfully, then the first
    argument will be `null` or `undefined`.
  - The third parameter is the passed instance of your _User_ _model_.
