"use strict";

const Bell = require("../..");
const Code = require("@hapi/code");
const Hapi = require("@hapi/hapi");
const Hoek = require("@hapi/hoek");
const Lab = require("@hapi/lab");

const Mock = require("../mock");

const internals = {};

const { describe, it } = (exports.lab = Lab.script());
const expect = Code.expect;

describe("github", () => {
  it("authenticates with mock", async (flags) => {
    const mock = await Mock.v2(flags);
    const server = Hapi.server({ host: "localhost", port: 80 });
    await server.register(Bell);

    const custom = Bell.providers.github();
    Hoek.merge(custom, mock.provider);

    const profile = {
      id: "1234567890",
      login: "steve",
      name: "steve",
      email: "steve@example.com",
      avatar_url: "https://github.com/images/error/octocat_happy.gif",
    };

    Mock.override("https://api.github.com/user", profile);

    server.auth.strategy("custom", "bell", {
      password: "cookie_encryption_password_secure",
      isSecure: false,
      clientId: "github",
      clientSecret: "secret",
      provider: custom,
    });

    server.route({
      method: "*",
      path: "/login",
      config: {
        auth: "custom",
        handler: function (request, h) {
          return request.auth.credentials;
        },
      },
    });

    const res1 = await server.inject("/login");
    const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";

    const res2 = await mock.server.inject(res1.headers.location);

    const res3 = await server.inject({
      url: res2.headers.location,
      headers: { cookie },
    });
    expect(res3.result).to.equal({
      provider: "custom",
      token: "456",
      expiresIn: 3600,
      refreshToken: undefined,
      query: {},
      state: { query: {} },
      profile: {
        id: "1234567890",
        username: "steve",
        displayName: "steve",
        email: "steve@example.com",
        image: "https://github.com/images/error/octocat_happy.gif",
        raw: profile,
      },
    });
  });

  it("authenticates with mock and custom uri", async (flags) => {
    const mock = await Mock.v2(flags);
    const server = Hapi.server({ host: "localhost", port: 80 });
    await server.register(Bell);

    const custom = Bell.providers.github({ uri: "http://example.com" });
    Hoek.merge(custom, mock.provider);

    const profile = {
      id: "1234567890",
      login: "steve",
      name: "steve",
      email: "steve@example.com",
      avatar_url: "https://github.com/images/error/octocat_happy.gif",
    };

    Mock.override("http://example.com/api/v3/user", profile);

    server.auth.strategy("custom", "bell", {
      password: "cookie_encryption_password_secure",
      isSecure: false,
      clientId: "github",
      clientSecret: "secret",
      provider: custom,
    });

    server.route({
      method: "*",
      path: "/login",
      config: {
        auth: "custom",
        handler: function (request, h) {
          return request.auth.credentials;
        },
      },
    });

    const res1 = await server.inject("/login");
    const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";

    const res2 = await mock.server.inject(res1.headers.location);

    const res3 = await server.inject({
      url: res2.headers.location,
      headers: { cookie },
    });
    expect(res3.result).to.equal({
      provider: "custom",
      token: "456",
      expiresIn: 3600,
      refreshToken: undefined,
      query: {},
      state: { query: {} },
      profile: {
        id: "1234567890",
        username: "steve",
        displayName: "steve",
        email: "steve@example.com",
        image: "https://github.com/images/error/octocat_happy.gif",
        raw: profile,
      },
    });
  });

  /**
   * https://docs.github.com/en/rest/reference/users#emails
   * The email key in the response is the publicly visible email address from the
   * user's profile. If they have the option in their settings "Public email" set to
   * "Don't show my email address" the email will be null. But since they've given
   * user:email scope consent, we're able to fetch their email address via
   * GET https://api.github.com/user/emails
   */
  it("authenticates when user has public email disabled on GitHub", async (flags) => {
    Mock.clear();
    const mock = await Mock.v2(flags);
    const server = Hapi.server({ host: "localhost", port: 80 });
    await server.register(Bell);

    const custom = Bell.providers.github();
    Hoek.merge(custom, mock.provider);

    server.auth.strategy("custom", "bell", {
      password: "cookie_encryption_password_secure",
      isSecure: false,
      clientId: "github",
      clientSecret: "secret",
      provider: custom,
    });

    const profileRequestMock = Mock.createProviderRequestMock({
      provider: "github",
      type: "profile-no-email",
    });

    const emailRequestMock = Mock.createProviderRequestMock({
      provider: "github",
      type: "email",
    });

    server.route({
      method: "*",
      path: "/login",
      config: {
        auth: "custom",
        handler: function (request, h) {
          return request.auth.credentials;
        },
      },
    });

    const res1 = await server.inject("/login");
    const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";

    const res2 = await mock.server.inject(res1.headers.location);

    const res3 = await server.inject({
      url: res2.headers.location,
      headers: { cookie },
    });
    const profile = {
      id: "1234567890",
      login: "githubuserjohnny",
      name: "johnny",
      email: "johnny@example.com",
      avatar_url: "https://github.com/images/error/octocat_happy.gif",
    };
    expect(res3.result).to.equal({
      provider: "custom",
      token: "456",
      expiresIn: 3600,
      refreshToken: undefined,
      query: {},
      state: { query: {} },
      profile: {
        id: "1234567890",
        username: "githubuserjohnny",
        displayName: "johnny",
        email: "johnny@example.com",
        image: "https://github.com/images/error/octocat_happy.gif",
        raw: profile,
      },
    });

    expect(profileRequestMock.pendingMocks()).to.equal([]);
    expect(emailRequestMock.pendingMocks()).to.equal([]);
  });
});
