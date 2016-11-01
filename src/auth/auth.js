module.exports = (function() {
  "use strict";

  // ExchangeTokens = require("./exchange");

  /**
   * Second part of oauth: request authorization
   */
  var RequestAuthorization = function(options, requestCompleted) {
    options.permissions = options.permissions || "read";
    var oauth_token = options.oauth_token,
        oauth_token_secret = options.oauth_token_secret,
        authURL = "https://www.flickr.com/services/oauth/authorize",
        browserURL = authURL + "?oauth_token=" + oauth_token + "&perms=" + options.permissions;
    return browserURL; 
  };

  return RequestAuthorization;
}());
