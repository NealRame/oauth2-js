var express = require('express');
var router = express.Router();

var debug = require('debug')('routes');
var inspect = require('util').inspect;

/* GET home page. */
router.get('/', function(req, res) {
    res.render('index', {title: 'NΞalRame'});
});

module.exports = router;
