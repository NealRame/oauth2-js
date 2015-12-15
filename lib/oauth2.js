var _ = require('underscore');
var crypto = require('crypto');
var debug = require('debug')('oauth2:lib');
var EventEmitter = require('events');
var express = require('express');
var format = require('util').format;
var http = require('http');
var https = require('https');
var path = require('path');
var querystring = require('querystring');
var uid = require('uid2');
var url = require('url');

var create_PEM = require('rsa-pem-from-mod-exp');

var endpoints = {};
var oauth2_certs = {};

function is_defined(v) {
    return v != undefined; // eslint-disable-line eqeqeq
}

function lookup(object, property_path) {
    if (is_defined(object)) {
        if (_.isString(property_path)) {
            return lookup(object, property_path.split('.'));
        }
        return (property_path.length === 0
            ? object
            : lookup(object[_.first(property_path)], _.rest(property_path))
        );
    }
}

function make_callback(resolve, reject) {
    return function(err) {
        if (err) {
            reject(err);
        } else {
            var args = _.rest(arguments);
            resolve.apply(null, args.length > 1 ? [args] : args);
        }
    };
}

function make_promise(fun) {
    var args = _.rest(arguments);
    return new Promise(function(resolve, reject) {
        fun.apply(null, args.concat(make_callback(resolve, reject)));
    });
}

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
        path: o.path || o.pathname
    };

    return protocol.request.bind(null, options);
}

function fetch_data(res) {
    return new Promise(
    function(resolve, reject) {
        var buffers = [];
        res.on('data', function(chunk) {
            buffers.push(
                (typeof chunk) === 'string' ? new Buffer(chunk) : chunk
            );
        });
        res.on('end', function() { resolve(Buffer.concat(buffers)); });
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
    debug('get_endpoint');
    var value = endpoints[key];
    return (value
        ? Promise.resolve(value)
        : get(
            'https://accounts.google.com/.well-known/openid-configuration',
            null
        ).then(function(data) {
            endpoints = JSON.parse(
                (typeof data) === 'string' ? data : data.toString()
            );
            return endpoints[key];
        }));
}

function fetch_endpoint(key, access_token) {
    debug('fetch_endpoint');
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
    debug('fetch_cert');
    if (attempts === 0) {
        return Promise.reject(
            new Error('No suitable key found to verify id_token')
        );
    }

    var cert = oauth2_certs[key_id];

    return (cert
        ? Promise.resolve(cert)
        : fetch_endpoint('jwks_uri', null)
            .then(function(data) {
                oauth2_certs = {};
                _.each(data.keys, function(key) {
                    oauth2_certs[key.kid] = create_PEM(key.n, key.e);
                });
                return fetch_cert(key_id, attempts - 1);
            }));
}

function verify_id_token(key_id, id_token, signature) {
    debug('verify_id_token');
    return fetch_cert(key_id, 2)
        .then(function(cert) {
            var verifier = crypto.createVerify('RSA-SHA256');
            verifier.update(id_token);
            return verifier.verify(cert, signature, 'base64');
        });
}

function get_id_token(credentials) {
    debug('get_id_token');
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

            if (!_.every(
                    ['access_token', 'expires_in', 'id_token'],
                    _.has.bind(null, data))) {
                throw new Error('Malformed token');
            }

            var segments = data.id_token.split('.');

            if (segments.length !== 3) {
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

var get_user_info = function(token) {
    debug('get_user_info');
    return fetch_endpoint('userinfo_endpoint', token);
};

function find_user(delegates, user_id) {
    debug(format('find_user: user_id=%j', user_id));
    return make_promise(delegates.find, user_id).then(function(user) {
        return is_defined(user) ? user : Promise.reject({status: 403});
    });
}

function init_user(delegates, user, token) {
    debug(format('init_user: user=%j, token=%j', user, token));
    return get_user_info(token.access_token).then(function(oauth2_user_info) {
        return make_promise(delegates.initialize, user, oauth2_user_info);
    });
}

function find_and_init_user(delegates, token, event_emitter) {
    debug(format('find_and_init_user: token=%j', token));
    return find_user(delegates, token.id_token.sub)
        .then(function(user) {
            return make_promise(delegates.isInitialized, user)
                .then(function(initialized) {
                    return initialized ? user : init_user(delegates, user, token);
                });
        })
        .then(function(user) {
            event_emitter.emit('login-success', user);
            return {token: token, user: user};
        })
        .catch(function(err) {
            event_emitter.emit('login-failure', token);
            return Promise.reject(err);
        });
}

function create_login_link(params, session) {
    debug(format('create_login_link: session=%j', session));
    params.state = session.csrf_token || (session.csrf_token = uid(32));
    debug(format('csrf_token: %s', params.state));
    return get_endpoint('authorization_endpoint').then(function(endpoint) {
        return format('%s?%s', endpoint, querystring.stringify(params));
    });
}

///
/// ## `OAuth2` Object.
///
/// #### OAuth2(params, delegates)
/// Construct a new `OAuth2` object given parameters to connect to the oauth2
/// provider and some delegate functions to map users data from the provider to
/// the application users data.
///
/// **Parameters:**
/// - `params`, _Required_.
///   A hash that contains the following attributes.
///   See [Google Developers Console](https://console.developers.google.com/)
///   to get them.
///   - `client_id`, _Required_. The client id value.
///   - `client_secret`, _Required_. The client secret value.
///   - `redirect_uri`, _Required_. The redirect uri value.
///
/// - `delegates`, _Required_.
///   A hash object containing four functions.
///   - `find(user_id, callback)`, _Required_.
///     See [`find`](#finduser_id-callback) for more details.
///   - `id(user)`, _Required_.
///     See [`id`](#iduser) for more details.
///   - `initialize`, _Required_.
///     See [`initialize`](#initializeoauth2_user_info-callback)
///     for more details.
///   - `isInitialized`, _Required_.
///     See [`isInitialized`](#is_initializeduser) for more details.
///
/// #### OAuth2#middleware
/// An express-js middleware. The middleware will provide locals
/// variables to views througth the response object:
/// * `loggedIn`, a flag indicating if the client is logged or not;
/// * if the user is logged:
///   - `user`, instance of _User_ _model_ matching the current session.
/// * if not:
///   - `loginLink`, a link leading to the login page.
///
/// #### OAuth2#route
/// An express-js router. The router will handle two distinct endpoints:
/// * `PREFIX/logout`,
/// * `PREFIX/oauth2_callback`.
///
/// The value of `PREFIX` is determined accordingly to the value you provide
/// for the `redirect_uri` endpoint.
/// Supposing you provide `'http://test.oauth2-js.io/auth/oauth2_callback'` as
/// the `redirect_uri` then PREFIX will be equal to 'auth'.
///
/// ### Delegates
///
/// You have to provide four delegates when your want to construct a `OAuth2`
/// object. Their are used to connect your appplication users logic with the
/// oauth2 provider.
/// - [`find`](#finduser_id-callback)
/// - [`id`](#iduser)
/// - [`initialize`](#initializeuser-oauth2_user_info-callback)
/// - [`isInitialized`](#is_initializeduser-callback)
///
/// #### find(user_id, callback)
/// Asynchronously associate an instance of your _User_ _model_ to a given
/// _Open ID_
/// [_token_id_](http://openid.net/specs/openid-connect-core-1_0.html#IDToken).
///
/// **Parameters:**
/// - `user_id`,
///   the value of the `sub` field of a an _Open ID token_id_.
/// * `callback`,
///   a completion callback respecting the nodejs completion callback pattern.
///   - The first argument is always reserved for an exception.
///     If the operation was completed successfully, then the first argument
///     will be `null` or `undefined`.
///   - The second parameter is an instance of your _User_ _model_.
///
/// #### initialize(user, oauth2_user_info, callback)
/// Asynchronously initialize a _User_ model instance with the _Open ID_
/// [_UserInfo_](http://openid.net/specs/openid-connect-core-1_0.html#UserInfo).
///
/// **Parameters:**
/// - `user`,
///   an instance of your _User_ _model_.
/// - `oauth2_user_info`,
///   the user info data from the oauth2 provider.
/// - `callback`,
///   a completion callback respecting the nodejs completion callbacks pattern.
///   - The first argument is always reserved for an exception.
///     If the operation was completed successfully, then the first
///     argument will be `null` or `undefined`.
///   - The third parameter is the passed instance of your _User_ _model_.
///
/// #### isInitialized(user, callback)
/// Asynchronously check if the given user is considered _initialized_
/// regarding to your _User_ _model_ state.
///
/// **Parameters:**
/// - `user`,
///   an instance of your _User_ _model_.
/// - `callback`,
///   a completion callback respecting the nodejs completion callback pattern.
///   - The first argument is always reserved for an exception.
///     If the operation was completed successfully, then the first
///     argument will be `null` or `undefined`.
///   - The second parameter of the callback is a boolean value, set to
///     `true` if and only if the user is considered initialized.
///
/// #### id(user)
/// Return the id of the given user.
///
/// **Parameters:**
/// - `user`,
///   an instance of your _User_ _model_.
function OAuth2(params, delegates) {
    debug(format('params: %j', params));
    debug(format('delegates: %j', delegates));

    if (!(this instanceof OAuth2)) {
        return new OAuth2(params, delegates);
    }

    // check if required parameters have been provided
    _.each(
        ['client_id', 'client_secret', 'redirect_uri'],
        function(attr) {
            if (!_.has(params, attr)) {
                throw new Error('Missing parameter: ' + attr);
            }
        }
    );

    // check if required delegates have been provided
    _.each(
        ['find', 'initialize', 'isInitialized'],
        function(delegate) {
            if (!_.has(delegates, delegate)) {
                throw new Error(format('Missing delegate: %s', delegate));
            }
        }
    );

    var parameters = _.defaults(_.clone(params), {
        prompt: 'select_account',
        response_type: 'code',
        scope: 'openid email'
    });

    Object.defineProperty(this, 'callbackPath', {
        value: url.parse(parameters.redirect_uri).path,
        enumerable: true
    });

    Object.defineProperty(this, 'logoutPath', {
        value: parameters.logout_path || path.join(path.dirname(this.callbackPath), 'logout'),
        enumerable: true
    });

    var event_emitter = this.events = new EventEmitter();

    this.middleware = (function(req, res, next) {
        var promise = null;
        if (req.path !== this.callbackPath) {
            debug('middleware: setting view locals variable');
            var session = req.session;
            if (session && session.userId) {
                var logout_path = this.logoutPath;
                promise = find_user(delegates, session.userId)
                    .then(function(user) {
                        return {
                            loggedIn: true,
                            logoutLink: logout_path,
                            user: user
                        };
                    })
                    .then(function(locals) {
                        _.extend(res.locals, locals);
                        req.auth = _.omit(locals, 'logoutLink');
                    });
            } else if (session) {
                promise = create_login_link(_.omit(parameters, 'client_secret'), session)
                    .then(function(link) {
                        return {
                            loggedIn: false,
                            loginLink: link
                        };
                    })
                    .then(function(locals) {
                        _.extend(res.locals, locals);
                        req.auth = _.omit(locals, 'loginLink');
                        session.redirectUri = req.path;
                    });
            } else {
                promise = Promise.reject(new Error('Undefined object \'session\''));
            }
        } else {
            debug('middleware: skipping callback route');
            promise = Promise.resolve();
        }
        promise.then(next.bind(null, null)).catch(next);
    }).bind(this);

    this.route = express.Router();

    this.route.get(this.logoutPath, function(req, res) {
        var session = req.session;

        delete session.loggedIn;
        delete session.tokens;
        delete session.userId;

        res.writeHead(302, {Location: '/'});
        res.end();
    });

    this.route
        .route(this.callbackPath)
        .all(function(req, res, next) {
            var state = lookup(req, 'query.state');
            var csrf_token = lookup(req, 'session.csrf_token');

            debug('req.session.csrf_token: ', req.session.csrf_token);
            debug('req.query.state: ', req.query.state);
            next(
                state && csrf_token && state === csrf_token
                    ? null
                    : _.extend(new Error('Unauthorized'), {status: 403})
            );
        })
        .get(function(req, res, next) {
            var session = req.session;
            var id_token_parameters = _.extend(
                _.pick(parameters, 'client_id', 'client_secret', 'redirect_uri'),
                {
                    code: req.query.code,
                    grant_type: 'authorization_code'
                }
            );
            get_id_token(id_token_parameters)
                .then(function(token) {
                    delete session.csrf_token;
                    return find_and_init_user(delegates, token, event_emitter);
                })
                .then(function(obj) {
                    session.loggedIn = true;
                    session.tokens = obj.tokens;
                    session.userId = delegates.id(obj.user);
                    res.writeHead(
                        302,
                        {Location: session.redirectUri ? session.redirectUri : '/'}
                    );
                    res.end();
                })
                .catch(next);
        });
}

module.exports = OAuth2;
