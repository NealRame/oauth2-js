var _ = require('underscore');
var crypto = require('crypto');
var debug = require('debug')('oauth2');
var express = require('express');
var format = require('util').format;
var https = require('https');
var http = require('http');
var path = require('path');
var Promise = require('promise');
var querystring = require('querystring');
var uid = require('uid2');
var url = require('url');

var create_PEM = require('rsa-pem-from-mod-exp');

var endpoints = {};
var oauth2_certs = {};

function prepare_request(endpoint, headers, method) {
    var o = url.parse(endpoint),
        protocol,
        port;

    if (o.protocol.match(/^https/i)) {
        protocol = https;
        port = o.port || 443;
    } else {
        protocol = http;
        port = o.port || 80;
    }

    var options = {
        headers: headers || {},
        method: method,
        port: port,
        hostname: o.host || o.hostname,
        path: o.path || o.pathname,
    };

    return protocol.request.bind(null, options);
}

function fetch_data(res) {
    return new Promise(
    function(resolve, reject) {
        var buffers = [];
        res.on('data', function(chunk) {
            buffers.push(
                typeof(chunk) === 'string' ? new Buffer(chunk) : chunk
            );
        });
        res.on('end', function() { resolve(Buffer.concat(buffers))});
        res.on('error', reject);
    });
}

function get(endpoint, headers) {
    var request = prepare_request(endpoint, headers, 'GET');

    return new Promise(
    function(resolve, reject) {
        request(function(res) {
            fetch_data(res).then(resolve, reject);
        }).end();
    });
}

function post(endpoint, headers, data) {
    if (data) {
        headers = headers || {};
        headers['Content-Length'] = data.length;
    }

    var request = prepare_request(endpoint, headers, 'POST');

    return new Promise(
    function(resolve, reject) {
        request(function(res) {
            fetch_data(res).then(resolve, reject);
        }).end(data);
    });
}

function get_endpoint(key) {
    var value = endpoints[key];
    return value
        ? new Promise.resolve(value)
        : get(
            'https://accounts.google.com/.well-known/openid-configuration',
            null
        ).then(function(data) {
            endpoints = JSON.parse(
                typeof(data) === 'string' ? data : data.toString()
            );
            return endpoints[key];
        });
}

function fetch_endpoint(key, access_token) {
    return get_endpoint(key)
        .then(function(endpoint) {
            var headers = null;
            if (access_token) {
                headers = {
                    Authorization: 'Bearer ' + access_token
                };
            }
            return get(endpoint, headers);
        })
        .then(function(data) {
            return JSON.parse(data);
        });
}

function fetch_cert(key_id, attempts) {
    if (attempts === 0) {
        return Promise.reject(
            new Error('No suitable key found to verify id_token')
        );
    }

    var cert = oauth2_certs[key_id];

    return cert
        ? new Promise.resolve(cert)
        : fetch_endpoint('jwks_uri', null)
            .then(function(data) {
                oauth2_certs = {};
                _.each(data.keys, function(key) {
                    oauth2_certs[key.kid] = create_PEM(key.n, key.e);
                });
                return fetch_cert(key_id, attempts - 1);
            });
}

function verify_id_token(key_id, id_token, signature) {
    return fetch_cert(key_id, 2)
        .then(function(cert) {
            var verifier = crypto.createVerify('RSA-SHA256');
            verifier.update(id_token);
            return verifier.verify(cert, signature, 'base64');
        });
}

function get_id_token(credentials) {
    return get_endpoint('token_endpoint')
        .then(function(endpoint) {
            return post(
                endpoint,
                {'Content-Type': 'application/x-www-form-urlencoded'},
                querystring.stringify(credentials)
            );
        })
        .then(function(data) {
            data = JSON.parse(data.toString());

            if (! _.every(
                    ['access_token', 'expires_in', 'id_token'],
                    _.has.bind(null, data))) {
                throw new Error('Malformed token');
            }

            var segments = data.id_token.split('.');

            if (segments.length != 3) {
                throw new Error('Malformed token');
            }

            var header = JSON.parse(
                (new Buffer(segments[0], 'base64')).toString());

            var claims = JSON.parse(
                (new Buffer(segments[1], 'base64')).toString());

            return new Promise(
            function(resolve, reject) {
                verify_id_token(header.kid, segments[0] + '.' + segments[1], segments[2])
                    .then(function(verified) {
                        resolve({
                            access_token: data.access_token,
                            id_token: claims,
                            expires_in: data.expires_in,
                            verified: verified
                        });
                    }, reject);
            });
        });
}

var get_user_info_ = function(token) {
    return fetch_endpoint('userinfo_endpoint', token);
};

///
/// # `OAuth2` Object.
///
///
/// ### Constructor
///
/// _Parameters_:
///
/// * `params`, _Required_.
///
///   A hash that contains the following attributes.
///   See [Google Developers Console](https://console.developers.google.com/)
///   to get them.
///
///   - `client_id`, _Required_.
///     The client id value.
///
///   - `client_secret`, _Required_.
///     The client secret value.
///
///   - `redirect_uri`, _Required_.
///     The redirect uri value.
///
/// * `helpers`, _Required_.
///
///   A hash object containing three functions helpers.
///
///   - `find_user`, _Required_.
///     See [`find_user`](#find_userid-callback) for more details.
///
///   - `is_initialized`, _Required_.
///     See [`is_initialized`](#is_initializeduser) for more details.
///
///   - `map_user`, _Required_.
///     See [`map_user`](#map_useroauth2_user_info-callback)
///     for more details.
///
///
/// ### Methods
///
/// #### `middleware()`
/// Returns an express-js middleware. The middleware will provide locals
/// variables to views througth the response object:
/// * `loggedIn`, a flag indicating if the client is logged or not;
/// * if the user is logged:
///   - `user`, instance of _User_ _model_ matching the current session.
/// * if not:
///   - `loginLink`, a link leading to the login page.
///
/// #### `route()`
/// Returns an express-js router. The router will handle two distinct
/// endpoints:
///
/// * `PREFIX/logout`,
/// * `PREFIX/oauth2_callback`.
///
/// The value of `PREFIX` is determined accordingly to the value you provide
/// for the `redirect_uri` endpoint.
/// Supposing you provide `'http://test.oauth2-js.io/auth/oauth2_callback'` as
/// the `redirect_uri` then PREFIX will be equal to 'auth'.
///
///
/// ### Helpers
///
/// You have to provide three helpers when your want to construct a `OAuth2`
/// object:
/// * [`find_user`](#find_userid-callback),
/// * [`is_initialized`](#is_initializeduser),
/// * [`map_user`](#map_useroauth2_user_info-callback).
///
/// #### `find_user(id, callback)`
/// Asynchronously associate an instance of your _User_ _model_ to a given
/// _Open ID_
/// [_token_id_](http://openid.net/specs/openid-connect-core-1_0.html#IDToken).
///
/// _Parameters_:
/// * `token_id`,
///   An _Open ID token_id_. According to how you have
///   configured your authentication request scope parameter, this is a
///   possible token value:
///     ```javascript
///     id_token: {
///         iss: 'URL',
///         sub: '[0-9a-zA-Z]+',
///         aud: '...',
///         exp: 1407534254989,
///         iat: 1407534288627
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
///
/// #### `is_initialized(user)`
/// Asynchronously check if the given user is considered _initialized_
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
///
/// #### `map_user(oauth2_user_info, callback)`
/// Asynchronously map the _ Open ID_
/// [_UserInfo_](http://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
/// attributes on the given instance of your _User_ _model_.
///
/// _Parameters_:
/// * `params`
///   A hash object containing the following attributes:
///   - `token`, see `find_user()` above for more details,
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
function OAuth2(params, helpers) {
    if (! this instanceof OAuth2) {
        return new OAuth2(openid);
    }

    // check if required parameters have been provided
    _.each(
        ['client_id', 'client_secret', 'redirect_uri'],
        function(attr) {
            if (! _.has(params, attr)) {
                throw new Error('Missing parameter: ' + attr);
            }
        }
    );

    // check if required helpers have been provided
    _.each(
        ['find_user', 'is_initialized', 'map_user'],
        function(helper) {
            if (! _.has(helpers, helper)) {
                throw new Error('Missing helper: ' + helper);
            }
        }
    );

    var parameters_ = _.defaults(_.clone(params), {
        prompt: 'select_account',
        response_type: 'code',
        scope: 'openid email'
    });
    var callbackPath_ = url.parse(parameters_.redirect_uri).path;
    var logoutPath_ = path.join(path.dirname(callbackPath_), 'logout');

    var findUser_ = function(userId) {
        return new Promise(function(resolve, reject) {
            helpers.find_user(userId, function(err, user) {
                if (err) {
                    reject(err);
                } else {
                    resolve(user);
                }
            });
        });
    };

    var isInitialized_ = function(user) {
        return new Promise(function(resolve, reject) {
            helpers.is_initialized(user, function(err, initialized) {
                if (err) {
                    reject(err);
                } else {
                    resolve({initialized: initialized, user: user});
                }
            });
        });
    };

    var initUser_ = function(user, token) {
        return get_user_info_(token.access_token)
            .then(function(oauth2_user_info) {
                return new Promise(
                    function(resolve, reject) {
                        helpers.map_user(
                            user,
                            oauth2_user_info,
                            function(err, user) {
                                if (err) {
                                    reject(err);
                                } else {
                                    resolve(user);
                                }
                            }
                        )
                    }
                );
            });
    };

    var findAndInitUser_ = function(token) {
        return findUser_(token.id_token.sub)
            .then(function(user) {
                return isInitialized_(user);
            })
            .then(function(res) {
                if (res.initialized) {
                    return res.user;
                } else {
                    return initUser_(res.user, token);
                }
            })
            .then(function(user) {
                return { token: token, user: user};
            });
    };

    var createLoginLink_  = function(session) {
        if (! session.loggedIn) {
            var csrf_token =
                session.csrf_token || (session.csrf_token = uid(32));

            debug('req.session.csrf_token: ', csrf_token);

            var params = _.extend(
                _.omit(parameters_, 'client_secret'),
                {state: csrf_token}
            );

            return get_endpoint('authorization_endpoint')
                .then(function(endpoint) {
                    return format('%s?%s',
                        endpoint, querystring.stringify(params));
                })
                .then(function(link) {
                    return link;
                });
        }
    };

    this.middleware = function() {
        return function(req, res, next) {
            var session = req.session;
            if (session) {
                if (session.loggedIn) {
                    findUser_(session.userId)
                        .then(function(user) {
                            res.locals.loggedIn = true;
                            res.locals.logoutLink = logoutPath_;
                            res.locals.user = user;
                            next();
                        })
                        .then(null, function(err) {
                            next(err);
                        });
                } else {
                    createLoginLink_(session)
                        .then(function(link) {
                            res.locals.loggedIn = false;
                            res.locals.loginLink = link;
                            next();
                        })
                        .then(null, function(err) {
                            next(err);
                        });
                }
            } else {
                next(
                    _.extend(
                        new Error('No session object defined!'), {status: 500}
                    )
                );
            }
        };
    };

    this.route = function() {
        var router = express.Router();

        router
            .route(logoutPath_)
            .get(function(req, res) {
                delete req.session.loggedIn;
                delete req.session.tokens;
                delete req.session.userId;
                res.writeHead(302, {
                    Location: '/',
                });
                res.end();
            });

        router
            .route(callbackPath_)
            .all(function(req, res, next) {
                debug('req.session.csrf_token: ', req.session.csrf_token);
                debug('req.query.state: ', req.query.state);
                next(
                    req.query.state === req.session.csrf_token
                        ? null
                        : _.extend(
                            new Error('Unauthorized'), {status: 403}
                        )
                );
            })
            .get(function(req, res) {
                var session = req.session;
                var params = _.extend(
                    _.pick(
                        parameters_, 'client_id', 'client_secret', 'redirect_uri'
                    ), {
                        code: req.query.code,
                        grant_type: 'authorization_code'
                    }
                );

                get_id_token(params)
                    .then(function(token) {
                        delete session.csrf_token;
                        return findAndInitUser_(token);
                    })
                    .then(function(obj) {
                        session.loggedIn = true;
                        session.tokens = obj.tokens;
                        session.userId = obj.user._id;
                        res.writeHead(302, {Location: '/'});
                        res.end();
                    })
                    .then(null, function(err) {
                        err.status = err.status || 500;
                        res.status(err.status).render('error', {
                            message: err.message,
                            error: err
                        });
                    });
            });

        return router;
    };
}

module.exports = OAuth2;
