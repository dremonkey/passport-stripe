/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError
  , Stripe = require('stripe');


/**
 * `Strategy` constructor.
 *
 * The Stripe authentication strategy authenticates requests by delegating to
 * Stripe using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and `stripe` object, which contains additional info as outlined
 * here: https://stripe.com/docs/connect/oauth.
 * The callback should then call the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Stipe application's client ID
 *   - `clientSecret`  your Stipe application's App Secret
 *   - `callbackURL`   URL to which Stipe will redirect the user after granting authorization
 *
 * Examples:
 *     StripeStrategy = require('passport-stripe').Strategy;
 *
 *     ...
 *
 *     passport.use(new StripeStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/stripe/callback'
 *       },
 *       function(accessToken, refreshToken, stripe, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://connect.stripe.com/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://connect.stripe.com/oauth/token';
  options.scopeSeparator = options.scopeSeparator || ',';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'stripe';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function (options) {
  return options;
};



/**
 * Retrieve user account info from Stripe.
 *
 * This overrides OAuth2Strategy.prototype.userProfile
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
  
  var stripe = Stripe(accessToken);

  stripe.account.retrieve(function (err, account) {
    if (err) {
      return done(new InternalOAuthError('Failed to fetch user account', err));
    }

    try {
      done(null, account)
    } 
    catch (e) {
      done(e)
    }
  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
