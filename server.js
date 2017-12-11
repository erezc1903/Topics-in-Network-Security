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

/**
 * Configure proxy middleware
 */
// var jsonPlaceholderProxy = proxy({
//     target: 'http://jsonplaceholder.typicode.com',
//     changeOrigin: true,             // for vhosted sites, changes host header to match to target's host
//     logLevel: 'debug'
// })

var app = express()

/**
 * Add the proxy to express
 */
// app.use('/users', jsonPlaceholderProxy)
app.use('/', function(req,res, next) {
    //console.log('requested app: ' + req.app);
    console.log('requested baseUrl: ' + req.baseUrl);
    //console.log('requested body: ' + req.body);
    //console.log('requested cookies: ' + req.cookies);
    //console.log('requested fresh: ' + req.fresh);
    //console.log('requested hostname: ' + req.hostname);
    //console.log('requested ip: ' + req.ip);
    //console.log('requested ips: ' + req.ips);
    //console.log('requested method: ' + req.method);
    //console.log('requested originalurl: ' + req.originalurl);
    //console.log('requested params: ' + req.params);
    //console.log('requested path: ' + req.path);
    //console.log('requested protocol: ' + req.protocol);
    //console.log('requested query: ' + req.query);
    console.log('request made at time: %d' + Date.now());
    next();
});
app.use('**', proxy({target: 'http://www.example.co.il', changeOrigin: true}));
app.listen(3000);


// app.listen(3000)
//
// console.log('[DEMO] Server: listening on port 3000')
// console.log('[DEMO] Opening: http://localhost:3000/users')
//
// require('opn')('http://localhost:3000/users')
