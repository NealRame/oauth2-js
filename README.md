OAuth2-JS
=========

Express-js middleware to login using Google accounts.


---
Install
-------

```sh
shell ~> npm intall --save git+http://
```


---
Example
-------

Rename the two files as following,
 - `test/oauth2.json.tmpl` as `test/oauth2.json`
 - `test/users.json.tmpl` as `test/users.json`
Edit with your settings, Then:

```sh
shell ~> npm test
```


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
    client_id: "GOOGLE_OAUTH2_CLIENT_ID",
    client_secret: "GOOGLE_OAUTH2_CLIENT_SECRET",
    redirect_uri: "OAUTH_REDIRECT_URI"
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
User model Helpers
------------------


### `find_user(id, callback)`

Asynchronously associate an instance of your _User_ _model_ to a given
_Open ID_ [_successful token response_](http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse).

_Parameters_:

* `token`

  An [Open ID successful token response]. According to how you have configured
  your authentication request scope parameter, this is a possible token value:
  ```javascript
  {
      access_token: 'SlAV32hkKG',
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: {
      iss: 'URL',               // REQUIRED
          sub: '[0-9a-zA-Z]+',  // REQUIRED
          aud: '...',           // REQUIRED
          exp: 1407534254989,   // REQUIRED
          iat: 1407534288627,   // REQUIRED
      }
  }
  ```

* `callback`

  A  completion callback respecting the nodejs completion callback pattern.

  - The first argument is always reserved for an exception. If the operation
    was completed successfully, then the first argument will be `null` or
    `undefined`.

  - The second parameter is a hash object containing the following attribute:
    ```javascript
    {
        token: { ... } // the passed token argument
        user:  { ... } // the matching instance of your _User_ _model_
    }
    ```


### `is_initialized(user)`

Asynchronously check if the given user is considered _initialized_ regarding to
your _User_ _model_ state.

_Parameters_:

* `params`

  A hash object containing the following attributes:

  - `token`, see `find_user()` above for more details,
  - `user`, an instance of your _User_ _model_.


* `callback`

  A  completion callback respecting the nodejs completion callback pattern.

  - The first argument is always reserved for an exception. If the operation
  was completed successfully, then the first argument will be `null` or
  `undefined`.

  - The second parameter of the callback is a boolean value, set to `true` if
  and only if the user is considered initialized.

  - The third parameter is a hash object containing the following attribute:
  ```javascript
  {
      token: { ... } // the passed token argument
      user:  { ... } // the matching instance of your _User_ _model_
  }
  ```


### `map_oauth2_user_info(oauth2_user_info, callback)`

Unsynchronously map the _ Open ID_ [_UserInfo_](http://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
attributes on the given instance of your _User_ _model_.

_Parameters_:

* `params`

  A hash object containing the following attributes:

  - `token`, see `find_user()` above for more details,
  - `user`, an instance of your _User_ _model_.


* `oauth2_user_info`
  A _UserInfo_ object.

* `callback`
  A  completion callback respecting the nodejs completion callbacks pattern.

  - The first argument is always reserved for an exception. If the operation
  was completed successfully, then the first argument will be `null` or
  `undefined`.

  - The second parameter is a hash object containing the following attribute:
  ```javascript
  {
      token: { ... } // the passed token argument
      user:  { ... } // the matching instance of your _User_ _model_
  }
  ```
