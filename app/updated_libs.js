/**
 * Script to download updated versions of vulnerable JavaScript libraries.
 * Run with: node update_libs.js
 */
var https = require('https');
var fs = require('fs');
var path = require('path');

var jsDir = path.join(__dirname, 'public', 'js');

function download(url, dest, cb) {
    var file = fs.createWriteStream(dest);
    https.get(url, function(response) {
        if (response.statusCode === 301 || response.statusCode === 302) {
            file.close();
            download(response.headers.location, dest, cb);
            return;
        }
        response.pipe(file);
        file.on('finish', function() {
            file.close(function() {
                console.log('Downloaded: ' + dest);
                cb(null);
            });
        });
    }).on('error', function(err) {
        fs.unlink(dest, function() {});
        cb(err);
    });
}

var libs = [
    {
        url: 'https://code.jquery.com/jquery-3.7.1.min.js',
        dest: path.join(jsDir, 'jquery.min.js'),
        name: 'jQuery 3.7.1'
    },
    {
        url: 'https://ajax.googleapis.com/ajax/libs/angularjs/1.8.3/angular.min.js',
        dest: path.join(jsDir, 'angular.min.js'),
        name: 'AngularJS 1.8.3'
    },
    {
        url: 'https://ajax.googleapis.com/ajax/libs/angularjs/1.8.3/angular-sanitize.min.js',
        dest: path.join(jsDir, 'angular-sanitize.min.js'),
        name: 'AngularJS Sanitize 1.8.3'
    }
];

var index = 0;
function next() {
    if (index >= libs.length) {
        console.log('All libraries updated successfully.');
        return;
    }
    var lib = libs[index++];
    console.log('Downloading ' + lib.name + '...');
    download(lib.url, lib.dest, function(err) {
        if (err) {
            console.error('Error downloading ' + lib.name + ': ' + err.message);
        }
        next();
    });
}
next();