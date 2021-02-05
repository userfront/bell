"use strict";

const internals = {};

exports = module.exports = function (options) {
  options = options || {};

  const uri = options.uri || "https://github.com";
  const user = options.uri
    ? options.uri + "/api/v3/user"
    : "https://api.github.com/user";

  return {
    protocol: "oauth2",
    useParamsAuth: true,
    auth: uri + "/login/oauth/authorize",
    token: uri + "/login/oauth/access_token",
    scope: ["user:email"],
    scopeSeparator: ",",
    headers: {
      "User-Agent": "hapi-bell-github",
    },
    profile: async function (credentials, params, get) {
      const profile = await get(user);

      // If user has public email disabled in their settings, fetch their primary
      // email from the /user/emails endpoint
      if (!profile.email) {
        const emails = await get("https://api.github.com/user/emails");

        if (emails.length) {
          const primaryEmailObj = emails.find((emailObj) => {
            return emailObj.primary === true;
          });

          profile.email = primaryEmailObj
            ? primaryEmailObj.email
            : emails[0].email;
        }
      }

      credentials.profile = {
        id: profile.id,
        username: profile.login,
        displayName: profile.name,
        email: profile.email,
        raw: profile,
      };
    },
  };
};
