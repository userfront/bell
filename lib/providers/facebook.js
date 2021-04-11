"use strict";

const Crypto = require("crypto");

const Hoek = require("@hapi/hoek");

const internals = {};

exports = module.exports = function (options) {
  const defaults = {
    fields: "id,name,email,first_name,last_name,middle_name,picture",
    scope: ["email"],
  };
  const settings = Hoek.applyToDefaults(defaults, options || {});

  return {
    protocol: "oauth2",
    useParamsAuth: true,
    auth: "https://www.facebook.com/v9.0/dialog/oauth",
    token: "https://graph.facebook.com/v9.0/oauth/access_token",
    scope: settings.scope,
    scopeSeparator: ",",
    profile: async function (credentials, params, get) {
      const query = {
        appsecret_proof: Crypto.createHmac("sha256", this.clientSecret)
          .update(credentials.token)
          .digest("hex"),
        fields: settings.fields,
      };

      const profile = await get("https://graph.facebook.com/v9.0/me", query);

      credentials.profile = {
        id: profile.id,
        displayName: profile.name,
        name: {
          first: profile.first_name,
          last: profile.last_name,
          middle: profile.middle_name,
        },
        email: profile.email,
        image: profile.picture.data.url,
        raw: profile,
      };
    },
  };
};
