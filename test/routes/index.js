var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res) {
    res.render('index', {title: 'Auth2-JS Test'});
});

module.exports = router;
