"use strict";

const crypto = require('crypto')
var algorithm = 'aes-256-ctr'

var request = require("request");
var Utils = require("./utils");

function encrypt (text) {
  var cipher = crypto.createCipher(algorithm, process.env.AUTH_AES_KEY)
  var crypted = cipher.update(text, 'utf8', 'hex')
  crypted += cipher.final('hex')
  return crypted
}

/**
 * The authentication function will sign into flickr as
 * an app, obtaining authorization keys values if it
 * does not already have them.
 */
var getAuthRequestToken = function(options, callback) {

  options = Object.assign({}, options)

  if(!options.requestOptions) options.requestOptions = {};

  options = Utils.setAuthVals(options);

  var queryArguments = {
        oauth_callback:         options.callback,
        oauth_consumer_key:     options.api_key,
        oauth_nonce:            options.oauth_nonce,
        oauth_timestamp:        options.oauth_timestamp,
        oauth_signature_method: "HMAC-SHA1",
        oauth_version:          "1.0"
      };

  var url = "https://www.flickr.com/services/oauth/request_token";
  var queryString = Utils.formQueryString(queryArguments);
  var data = Utils.formBaseString("GET", url, queryString);
  var signature = Utils.sign(data, options.secret);

  var flickrURL = url + "?" + queryString + "&oauth_signature=" + signature;

  request.get(flickrURL, function(error, response, body) {

    if(error) return callback(error);

    // show response
    response = Utils.parseRestResponse(body);
    if(!response) {
      return callback(new Error("bad response"));
    }

    if(response.oauth_problem) {
      // Occasionally, this will fail.
      // Rerunning it then succeeds just fine.
      console.log('response.oauth_problem ' + response.oauth_problem)
      return callback(response.oauth_problem);
    }
    Object.keys(response).forEach(function(key) {
      options[key] = response[key];
    });

    options.permissions = options.permissions || "read";
    var oauth_token_secret = options.oauth_token_secret;
    oauth_token_secret = encrypt( oauth_token_secret )
    var oauth_token = options.oauth_token,
      authURL = "https://www.flickr.com/services/oauth/authorize",
      browserURL = authURL + "?oauth_token=" + oauth_token + "&perms=" + options.permissions
    return callback(false, browserURL, oauth_token_secret);
  });
};

var processAuthCallback = function(options, tokens, callback){

  options = Object.assign({}, options)
  options = Utils.setAuthVals(options);

  var queryArguments = {
    oauth_consumer_key:     options.api_key,
    oauth_nonce:            options.oauth_nonce,
    oauth_signature_method: "HMAC-SHA1",
      oauth_timestamp:        options.oauth_timestamp,
      oauth_version: "1.0",
      // new values:
      oauth_token: tokens.oauth_token,
      oauth_verifier: tokens.oauth_verifier
    };
    var url = "https://www.flickr.com/services/oauth/access_token"
    var queryString = Utils.formQueryString(queryArguments);
    var data = Utils.formBaseString("GET", url, queryString);
    var signature = Utils.sign(data, options.secret, options.oauth_token_secret);
    var flickrURL = url + "?" + queryString + "&oauth_signature=" + signature;

    request.get(flickrURL, function(error, response, body) {
      if(error) return callback(error);
      return callback(false, Utils.parseRestResponse(body));
    });
  };

  var getAPI = function(options, callback) {
    options = Object.assign({}, options)
    if(!options.requestOptions) options.requestOptions = {};
    var APIBuilder = require("./flickr-api-object");
    new APIBuilder(options, Utils, callback);
  };

/**
 * The initial Flickr access point.
 */
module.exports = {
  getAuthRequestToken: getAuthRequestToken,
  processAuthCallback: processAuthCallback,
  getAPI: getAPI
};

