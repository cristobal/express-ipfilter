/*!
 * Express - IP Filter
 * Copyright(c) 2014 Bradley and Montgomery Inc.
 * MIT Licensed
 */

'use strict';

/**
 * Module dependencies.
 */
var assign = require('lodash/object/assign');
var find = require('lodash/collection/find');
var isArray = require('lodash/lang/isArray');
var isEmpty = require('lodash/lang/isEmpty');
var isFunction = require('lodash/lang/isFunction');
var has = require('lodash/object/has');
var map = require('lodash/collection/map');
var ip = require('ip');
var Netmask = require('netmask').Netmask;

function processReq(req, settings, cache) {
    // cache regexp's
    if (!has(cache, 'processReq')) {
        var fn = function (items) {
            if (isEmpty(items)) {
                return [];
            }

            return map(items, function (item) {
                return new RegExp(item);
            });
        };

        cache.processReq = {};
        cache.processReq.match = fn(settings.match);
        cache.processReq.excluding = fn(settings.excluding);
    }

    var url = req.url;
    var f = function (item) {
        return item.test(url);
    };

    var g = function (ops) {
        return ops.length > 0 && find(ops, f) !== void 0;
    };

    var isMatching = g(cache.processReq.match);
    var isExcluding = g(cache.processReq.excluding);

    // if url matches and should not be excluded, this request should be processed
    if (isMatching && !isExcluding) {
        return true;
    }
    // if url is in the excluding list, this request should not be processed
    else if (isExcluding) {
        return false;
    }

    // default is to process given url route
    return true;
}

function getClientIp(req) {
    var ipAddress;
    var headers = req.headers;

    // parse ipAddress from x-forwarded-for if it exists and is not empty
    if (has(headers, 'x-forwarded-for') && !isEmpty(headers['x-forwarded-for'])) {
        ipAddress = headers['x-forwarded-for'].split(',')[0];
    }

    // set ip address if not set by x-forwarded-for
    if (!ipAddress) {
        ipAddress = req.connection.remoteAddress;
    }

    // parse ipAddress from cloudflare connecting client IP if it exists and is not empty
    if (has(headers, 'cf-connecting-ip') && !isEmpty(headers['cf-connecting-ip'])) {
        ipAddress = headers['cf-connecting-ip'];
    }

    // return empty ipAddress if no ipAddress has been set
    if (!ipAddress) {
        return '';
    }

    if (ipAddress.indexOf(':') !== -1) {
        ipAddress = ipAddress.split(':')[0];
    }

    return ipAddress;
}

function hasAccess(ipAddress, ips, req, settings, cache) {
    if (!has(cache, 'hasAccess')) {
        cache.hasAccess = {};
        cache.hasAccess.mode = settings.mode.toLowerCase();
        cache.hasAccess.blocks = [];
        cache.hasAccess.ranges = [];
        if (settings.cidr && ips.length > 0) {
            cache.hasAccess.blocks = map(ips, function (value) {
                return new Netmask(value);
            });
        }
        else if (settings.ranges && ips.length > 0) {
            cache.hasAccess.ranges = map(ips, function (value) {
                var flag = isArray(value);
                if (flag && value.length > 1) {
                    return [ip.toLong(value[0]), ip.toLong(value[1])];
                }

                return flag ? value[0] : value;
            });
        }
    }

    var mode = cache.hasAccess.mode;
    var allowedIp = false;
    var notBannedIp = false;
    var isPrivateIpOkay = false; // Normalize mode
    var blocks = cache.hasAccess.blocks;
    var ranges = cache.hasAccess.ranges;
    var isPrivate = ip.isPrivate(ipAddress);

    if (settings.cidr) {
        var cidrFlag = false;
        for (var i = 0, l = blocks.length; i < l; i++) {
            if (blocks[i].contains(ipAddress)) {
                cidrFlag = true;
                break;
            }
        }
        if (cidrFlag) {
            allowedIp = mode === 'allow';
        }
        else {
            notBannedIp = mode === 'deny';
            isPrivateIpOkay = settings.allowPrivateIPs && isPrivate;
        }
    }
    else if (settings.ranges) {
        var rangesFlag = false;
        var longIp = ip.toLong(ipAddress);
        for (var j = 0, k = ranges.length; j < k; j++) {
            var range = ranges[j];
            if (isArray(range) && (longIp >= range[0] && longIp <= range[1])) {
                rangesFlag = true;
                break;
            }
            else if (ipAddress === range) {
                rangesFlag = true;
                break;
            }
        }

         allowedIp = (mode === 'allow') && rangesFlag;
         notBannedIp = (mode === 'deny') && !rangesFlag;
         isPrivateIpOkay = settings.allowPrivateIPs && isPrivate && !((mode === 'deny') && rangesFlag);
    }
    else {
        var containsIPAddress = ips.indexOf(ipAddress) !== -1;
        allowedIp = (mode === 'allow') && containsIPAddress;
        notBannedIp = (mode === 'deny') && !containsIPAddress;
        isPrivateIpOkay = settings.allowPrivateIPs && isPrivate && !((mode === 'deny') && containsIPAddress);
    }

    return allowedIp || notBannedIp || isPrivateIpOkay;
}

/**
 * express-ipfilter:
 *
 * IP Filtering middleware;
 *
 * Examples:
 *
 *      var ipfilter = require('ipfilter'),
 *          ips = ['127.0.0.1'];
 *
 *      app.use(ipfilter(ips));
 *
 * Options:
 *
 *  - `mode` whether to deny or grant access to the IPs provided. Defaults to 'deny'.
 *  - `log` console log actions. Defaults to true.
 *  - `errorCode` the HTTP status code to use when denying access. Defaults to 401.
 *  - `errorMessage` the error message to use when denying access. Defaults to 'Unauthorized'.
 *  - `allowPrivateIPs` whether to grant access to any IP using the private IP address space unless explicitly denied. Defaults to false.
 *  - 'cidr' whether ips are ips with a submnet mask.  Defaults to 'false'.
 *  - 'ranges' whether ranges are supplied as ips
 *  - 'match' routes that should be matched for ip filtering
 *  - 'excluding' routes that should be excluded from ip filtering
 *
 * @param [Array] IP addresses
 * @param {Object} options
 * @api public
 */
module.exports = function ipfilter(ips, opts) {
    // assign settings
    var settings = assign({}, {
        mode: 'deny',
        log: true,
        logF: undefined,
        errorCode: 401,
        errorMessage: 'Unauthorized',
        allowPrivateIPs: false,
        cidr: false,
        ranges: false,
        match: [],
        excluding: []
    }, opts);

    // cache object
    var cache = {};

    // initialize ips to empty array if it's not an array
    if (!isArray(ips)) {
        ips = [];
    }

    // set default logger if not set
    if (!isFunction(settings.logF)) {
        settings.logF = console.log;
    }

    // log wrapper
    var log = function (message) {
        if (settings.log) {
            settings.logF(message);
        }
    };

    return function (req, res, next) {
        // wether we should process this request or not
        if (!processReq(req, settings, cache)) {
            log('Access granted for path:' + req.url);
            return next();
        }

        // wether the request has acesss to the given resource
        var ipAddress = getClientIp(req);
        if (hasAccess(ipAddress, ips, req, settings, cache)) {
            log('Access granted to IP address: ' + ipAddress);
            return next();
        }

        // Deny access
        log('Access denied to IP address: ' + ipAddress);
        res.statusCode = settings.errorCode;
        return res.end(settings.errorMessage);
    };
};
