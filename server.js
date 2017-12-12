/**
 * Created by Erez on 07/12/2017.
 */
/**
 * Module dependencies.
 */

 /* test for how to work with git */
 /* test for branching */
var express = require('express');
var proxy = require('http-proxy-middleware');


var app = express();

// proxy middleware options
var options = {
        target: 'http://www.example.org', // target host
        changeOrigin: true,               // needed for virtual hosted sites
        pathRewrite: function (path, req) {
          console.log('pathRewrite path: ' + path);
          console.log('pathRewrite path type: ' + (typeof path));
          console.log('pathRewrite req hostname: ' + req.hostname);
          var a = path.replace('http://morfix.org/', 'http://ynet.co.il');
          console.log('a: ' + a);
          return a;
        },
        //router: function(req) { return 'http://' + req.hostname; }
    };
var exampleProxy = proxy(options);

/**
 * Add the proxy to express
 */
app.use(function(req, res, next) {
    console.log('requested baseUrl: ' + req.hostname);
    var time = new Date();
    console.log('request made at: ' +
                time.getHours() + ":" +
                time.getMinutes() + ":" +
                time.getSeconds());
    next();
});
app.use(exampleProxy);

console.log("Listening on port 3000");
app.listen(3000);



















// var express = require('express');
// var proxy = require('http-proxy-middleware');
//
// var app = express();
//
// app.use('**', proxy({target: 'http://www.example.org', changeOrigin: true}));
// app.listen(3000);
