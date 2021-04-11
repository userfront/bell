"use strict";

const internals = {};

/**
 * https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-overview
 * https://docs.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
 * https://docs.microsoft.com/en-us/graph/api/profilephoto-get?view=graph-rest-1.0
 */

exports = module.exports = function (options) {
  options = options || {};
  const tenantId = options.tenant || "common";

  return {
    protocol: "oauth2",
    useParamsAuth: true,
    auth: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
    token: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    scope: [
      "openid",
      "offline_access", // Enable app to get refresh_tokens
      "profile", // Get basic info such as name, preferred username and objectId
      "user.read", // Read basic user info through /me endpoint
    ],
    profile: async function (credentials, params, get) {
      const profile = await get("https://graph.microsoft.com/v1.0/me");
      const image = await get(
        "https://graph.microsoft.com/v1.0/me/photos/240x240/$value"
      );
      const base64Image = Buffer.from(image).toString("base64");

      credentials.profile = {
        id: profile.id,
        displayName: profile.displayName,
        email: profile.userPrincipalName || profile.mail,
        image: `data:image/jpeg;base64,${base64Image}`,
        raw: profile,
      };
    },
  };
};
