"use strict";

const Boom = require("@hapi/boom");
const Code = require("@hapi/code");
const Hapi = require("@hapi/hapi");
const Hoek = require("@hapi/hoek");
const Lab = require("@hapi/lab");

const Bell = require("../lib");
const OAuth = require("../lib/oauth");
const Mock = require("./mock");
const privateKey = require("./constants.json").privateKey;

const { describe, it } = (exports.lab = Lab.script());
const expect = Code.expect;

describe("Bell", () => {
  describe("v1()", () => {
    it("errors on missing oauth_verifier", async () => {
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: "twitter",
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res = await server.inject("/login?oauth_token=123");
      expect(res.statusCode).to.equal(500);
    });

    it("attempts to perform html redirection on missing cookie on token step", async () => {
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: "twitter",
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res = await server.inject(
        "/login?oauth_token=123&oauth_verifier=123"
      );
      expect(res.statusCode).to.equal(200);
      expect(res.result).to.equal(
        '<html><head><meta http-equiv="refresh" content="0;URL=\'http://localhost:8080/login?oauth_token=123&oauth_verifier=123&refresh=1\'"></head><body></body></html>'
      );
    });

    it("errors on missing cookie on token step (with refresh)", async () => {
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: "twitter",
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res = await server.inject(
        "/login?oauth_token=123&oauth_verifier=123&refresh=1"
      );
      expect(res.statusCode).to.equal(500);
    });

    it("errors on rejected/denied query parameter", async () => {
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: "twitter",
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res = await server.inject("/login?error=access_denied");
      expect(res.statusCode).to.equal(500);
      const res2 = await server.inject("/login?denied=true");
      expect(res2.statusCode).to.equal(500);
    });

    it("fails getting temporary credentials", async (flags) => {
      const mock = await Mock.v1(flags, { failTemporary: true });
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res = await server.inject("/login");
      expect(res.statusCode).to.equal(500);
    });

    it("fails getting token credentials", async (flags) => {
      const mock = await Mock.v1(flags, { failToken: true });
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
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
      expect(res3.statusCode).to.equal(500);
    });

    it("passes credentials on error (temporary error)", async (flags) => {
      const mock = await Mock.v1(flags, { failTemporary: true });
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: {
            strategy: "custom",
            mode: "try",
          },
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res = await server.inject("/login?some=thing");
      expect(res.result).to.equal({
        provider: "custom",
        query: { some: "thing" },
      });
    });

    it("passes credentials on error (token error)", async (flags) => {
      const mock = await Mock.v1(flags, { failToken: true });
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: {
            strategy: "custom",
            mode: "try",
          },
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res1 = await server.inject("/login?some=thing");
      const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";

      const res2 = await mock.server.inject(res1.headers.location);

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      });
      expect(res3.result).to.equal({
        provider: "custom",
        query: { some: "thing" },
      });
    });

    it("does not pass on runtime query params by default", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res = await server.inject("/login?runtime=true");
      expect(res.headers.location).to.equal(mock.uri + "/auth?oauth_token=1");
    });

    it("passes on runtime query params with allowRuntimeProviderParams", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
        allowRuntimeProviderParams: true,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res = await server.inject("/login?runtime=true");
      expect(res.headers.location).to.equal(
        mock.uri + "/auth?oauth_token=1&runtime=true"
      );
    });

    it("authenticates an endpoint via oauth with auth provider parameters", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
        providerParams: {
          special: true,
        },
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res1 = await server.inject("/login");
      expect(res1.headers.location).to.equal(
        mock.uri + "/auth?special=true&oauth_token=1"
      );

      const res2 = await mock.server.inject(res1.headers.location);
      expect(res2.headers.location).to.equal(
        "http://localhost:8080/login?oauth_token=1&oauth_verifier=123&extra=true"
      );
    });

    it("authenticates an endpoint via oauth with a function as provider parameters", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
        providerParams: (request) => ({
          value: request.query.foo,
        }),
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res1 = await server.inject("/login?foo=bar");
      expect(res1.headers.location).to.equal(
        mock.uri + "/auth?value=bar&oauth_token=1"
      );

      const res2 = await mock.server.inject(res1.headers.location);
      expect(res2.headers.location).to.equal(
        "http://localhost:8080/login?oauth_token=1&oauth_verifier=123&extra=true"
      );
    });

    it("passes profileParams", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      const custom = Bell.providers.twitter();
      Hoek.merge(custom, mock.provider);

      const override = new Promise((resolve) => {
        Mock.override("https://api.twitter.com/1.1/users/show.json", (uri) => {
          expect(uri).to.equal(
            "https://api.twitter.com/1.1/users/show.json?user_id=1234567890&fields=id%2Cemail"
          );
          resolve();
        });
      });

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "twitter",
        clientSecret: "secret",
        provider: custom,
        profileParams: {
          fields: "id,email",
        },
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res1 = await server.inject("/login");
      const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";

      const res2 = await mock.server.inject(res1.headers.location);
      await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      });

      await override;
    });

    it("errors on invalid resource request (mock Twitter)", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      const custom = Bell.providers.twitter();
      Hoek.merge(custom, mock.provider);

      Mock.override(
        "https://api.twitter.com/1.1/users/show.json",
        Boom.badRequest()
      );

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "twitter",
        clientSecret: "secret",
        provider: custom,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res1 = await server.inject("/login");
      const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";
      expect(res1.headers.location).to.equal(mock.uri + "/auth?oauth_token=1");

      const res2 = await mock.server.inject(res1.headers.location);
      expect(res2.headers.location).to.equal(
        "http://localhost:8080/login?oauth_token=1&oauth_verifier=123"
      );

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      });
      expect(res3.statusCode).to.equal(500);
    });

    it("authenticates with mock Twitter with skip profile", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      const custom = Bell.providers.twitter();
      Hoek.merge(custom, mock.provider);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "twitter",
        clientSecret: "secret",
        provider: custom,
        skipProfile: true,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
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
        token: "final",
        secret: "secret",
        query: {},
      });
    });

    it("errors on mismatching token", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res1 = await server.inject("/login");
      const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";
      expect(res1.headers.location).to.equal(mock.uri + "/auth?oauth_token=1");

      await mock.server.inject(res1.headers.location);

      const res2 = await server.inject({
        url: "http://localhost:8080/login?oauth_token=2&oauth_verifier=123",
        headers: { cookie },
      });
      expect(res2.statusCode).to.equal(500);
    });

    it("errors if isSecure is true when protocol is not https", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: true,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: (request, h) => {
            return request.auth.credentials;
          },
        },
      });

      const res = await server.inject("/login");
      expect(res.statusCode).to.equal(500);
    });

    it("passes if isSecure is true when protocol is https (forced)", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        isSecure: true,
        password: "cookie_encryption_password_secure",
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
        forceHttps: true,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: (request, h) => {
            return request.auth.credentials;
          },
        },
      });

      const res1 = await server.inject("/login");
      const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";

      const res2 = await mock.server.inject(res1.headers.location);
      expect(res2.headers.location).to.contain(
        "https://localhost:8080/login?oauth_token=1&oauth_verifier="
      );

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      });
      expect(res3.statusCode).to.equal(200);
    });

    it("passes if isSecure is true when protocol is https (location)", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: true,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
        location: "https://differenthost:8888",
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: (request, h) => {
            return request.auth.credentials;
          },
        },
      });

      const res1 = await server.inject("/login");
      const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";

      const res2 = await mock.server.inject(res1.headers.location);
      expect(res2.headers.location).to.contain(
        "https://differenthost:8888/login?oauth_token=1&oauth_verifier="
      );

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      });
      expect(res3.statusCode).to.equal(200);
    });

    it("forces https in callback_url when set in options", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
        forceHttps: true,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res1 = await server.inject("/login");
      const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";

      const res2 = await mock.server.inject(res1.headers.location);
      expect(res2.headers.location).to.contain(
        "https://localhost:8080/login?oauth_token=1&oauth_verifier="
      );

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      });
      expect(res3.statusCode).to.equal(200);
    });

    it("uses location setting in callback_url when set in options", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
        location: "https://differenthost:8888",
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            return request.auth.credentials;
          },
        },
      });

      const res1 = await server.inject("/login");
      const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";

      const res2 = await mock.server.inject(res1.headers.location);
      expect(res2.headers.location).to.contain(
        "https://differenthost:8888/login?oauth_token=1&oauth_verifier="
      );

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      });
      expect(res3.statusCode).to.equal(200);
    });

    it("returns resource response stream", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            const client = new Bell.oauth.Client({
              name: "twitter",
              provider: mock.provider,
              clientId: "test",
              clientSecret: "secret",
            });

            const credentials = request.auth.credentials;
            return client.resource("GET", mock.uri + "/resource", null, {
              token: credentials.token,
              secret: credentials.secret,
              stream: true,
            });
          },
        },
      });

      const res1 = await server.inject("/login?next=%2Fhome");
      const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";
      expect(res1.headers.location).to.equal(mock.uri + "/auth?oauth_token=1");

      const res2 = await mock.server.inject(res1.headers.location);
      expect(res2.headers.location).to.equal(
        "http://localhost:8080/login?oauth_token=1&oauth_verifier=123"
      );

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      });
      expect(res3.result).to.equal("some text reply");
    });

    it("returns raw resource response", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: async function (request, h) {
            const client = new Bell.oauth.Client({
              name: "twitter",
              provider: mock.provider,
              clientId: "test",
              clientSecret: "secret",
            });

            const credentials = request.auth.credentials;
            const { payload } = await client.resource(
              "POST",
              mock.uri + "/resource",
              { a: 5 },
              {
                token: credentials.token,
                secret: credentials.secret,
                raw: true,
              }
            );
            return payload;
          },
        },
      });

      const res1 = await server.inject("/login?next=%2Fhome");
      const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";
      expect(res1.headers.location).to.equal(mock.uri + "/auth?oauth_token=1");

      const res2 = await mock.server.inject(res1.headers.location);
      expect(res2.headers.location).to.equal(
        "http://localhost:8080/login?oauth_token=1&oauth_verifier=123"
      );

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      });
      expect(res3.result).to.equal('{"a":"5"}');
    });

    it("returns resource POST response", async (flags) => {
      const mock = await Mock.v1(flags);
      const server = Hapi.server({
        host: "localhost",
        port: 8080,
      });
      await server.register(Bell);

      server.auth.strategy("custom", "bell", {
        password: "cookie_encryption_password_secure",
        isSecure: false,
        clientId: "test",
        clientSecret: "secret",
        provider: mock.provider,
      });

      server.route({
        method: "*",
        path: "/login",
        options: {
          auth: "custom",
          handler: function (request, h) {
            const client = new Bell.oauth.Client({
              name: "twitter",
              provider: mock.provider,
              clientId: "test",
              clientSecret: "secret",
            });

            const credentials = request.auth.credentials;
            return client.resource(
              "POST",
              mock.uri + "/resource",
              { a: 5 },
              {
                token: credentials.token,
                secret: credentials.secret,
                stream: true,
              }
            );
          },
        },
      });

      const res1 = await server.inject("/login?next=%2Fhome");
      const cookie = res1.headers["set-cookie"][0].split(";")[0] + ";";
      expect(res1.headers.location).to.equal(mock.uri + "/auth?oauth_token=1");

      const res2 = await mock.server.inject(res1.headers.location);
      expect(res2.headers.location).to.equal(
        "http://localhost:8080/login?oauth_token=1&oauth_verifier=123"
      );

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      });
      expect(res3.result).to.equal('{"a":"5"}');
    });
  });

  describe("Client", () => {
    it("accepts empty client secret", () => {
      const client = new OAuth.Client({
        provider: Bell.providers.twitter(),
      });
      expect(client.settings.clientSecret).to.equal("&");
    });

    describe("_request()", () => {
      it("errors on failed request", async () => {
        Mock.override("http://example.com/", null);

        const client = new OAuth.Client({
          provider: Bell.providers.twitter(),
        });
        await expect(
          client._request(
            "get",
            "http://example.com/",
            null,
            { oauth_token: "xcv" },
            {
              secret: "secret",
              desc: "type",
            }
          )
        ).to.reject("Failed obtaining undefined type");

        Mock.clear();
      });

      it("errors on invalid response", async () => {
        Mock.override("http://example.com/", "{x");

        const client = new OAuth.Client({
          name: "prov",
          provider: Bell.providers.twitter(),
        });
        await expect(
          client._request(
            "get",
            "http://example.com/",
            null,
            { oauth_token: "xcv" },
            {
              secret: "secret",
              desc: "type",
            }
          )
        ).to.reject("Received invalid payload from prov type endpoint");

        Mock.clear();
      });

      it("errors on invalid response (no desc)", async () => {
        Mock.override("http://example.com/", "{x");

        const client = new OAuth.Client({
          name: "prov",
          provider: Bell.providers.twitter(),
        });
        await expect(
          client._request(
            "get",
            "http://example.com/",
            null,
            { oauth_token: "xcv" },
            { secret: "secret" }
          )
        ).to.reject("Received invalid payload from prov resource endpoint");

        Mock.clear();
      });
    });

    describe("baseUri()", () => {
      it("removes default port", () => {
        expect(OAuth.Client.baseUri("http://example.com:80/x")).to.equal(
          "http://example.com/x"
        );
        expect(OAuth.Client.baseUri("https://example.com:443/x")).to.equal(
          "https://example.com/x"
        );
      });

      it("keeps non-default port", () => {
        expect(OAuth.Client.baseUri("http://example.com:8080/x")).to.equal(
          "http://example.com:8080/x"
        );
        expect(OAuth.Client.baseUri("https://example.com:8080/x")).to.equal(
          "https://example.com:8080/x"
        );
      });
    });

    describe("signature()", () => {
      it("generates RFC 5849 example", () => {
        const client = new OAuth.Client({
          clientId: "9djdj82h48djs9d2",
          clientSecret: "j49sk3j29djd",
          provider: Bell.providers.twitter(),
        });
        const tokenSecret = "dh893hdasih9";

        const params = {
          b5: "=%3D",
          a3: ["a", "2 q"],
          "c@": "",
          a2: "r b",
          c2: "",
        };

        const oauth = {
          oauth_consumer_key: "9djdj82h48djs9d2",
          oauth_token: "kkk9d7dh3k39sjv7",
          oauth_signature_method: "HMAC-SHA1",
          oauth_timestamp: "137131201",
          oauth_nonce: "7d8f3e4a",
        };

        const signature = client.signature(
          "post",
          "http://example.com/request",
          params,
          oauth,
          tokenSecret
        );
        expect(signature).to.equal("r6/TJjbCOr97/+UU0NsvSne7s5g=");
      });

      it("computes RSA-SHA1 signature", () => {
        const client = new OAuth.Client({
          clientId: "9djdj82h48djs9d2",
          clientSecret: privateKey,
          provider: {
            protocol: "oauth",
            auth: "https://example.com/oauth/authorize",
            token: "https://example.com/oauth/access-token",
            temporary: "https://example.com/oauth/request-token",
            signatureMethod: "RSA-SHA1",
          },
        });

        const params = {
          b5: "=%3D",
          a3: ["a", "2 q"],
          "c@": "",
          a2: "r b",
          c2: "",
        };

        const oauth = {
          oauth_consumer_key: "9djdj82h48djs9d2",
          oauth_token: "kkk9d7dh3k39sjv7",
          oauth_signature_method: "RSA-SHA1",
          oauth_timestamp: "137131201",
          oauth_nonce: "7d8f3e4a",
        };

        const signature = client.signature(
          "get",
          "http://example.com/request",
          params,
          oauth,
          privateKey
        );
        expect(signature).to.equal(
          "mUUxSJS/cfLML3eZMlLK7eYxN36hWeBf4gGkAQbEc0bjz2GTH7YVaW2bQ+wwkHuWwxOTSLD70FJxVV4fmGIyw+/l7kt1FaJepL3Uc7IcARhUzsdT9HXRcHFjRkyDvBSssZA6LksQjGyblpYv5LXtUtVTm+IFR19ZwovFjIvNBxM="
        );
      });

      it("handles array param with reveresed order", () => {
        const client = new OAuth.Client({
          clientId: "9djdj82h48djs9d2",
          clientSecret: "j49sk3j29djd",
          provider: Bell.providers.twitter(),
        });
        const tokenSecret = "dh893hdasih9";

        const params = {
          b5: "=%3D",
          a3: ["2 q", "a"],
          "c@": "",
          a2: "r b",
          c2: "",
        };

        const oauth = {
          oauth_consumer_key: "9djdj82h48djs9d2",
          oauth_token: "kkk9d7dh3k39sjv7",
          oauth_signature_method: "HMAC-SHA1",
          oauth_timestamp: "137131201",
          oauth_nonce: "7d8f3e4a",
        };

        const signature = client.signature(
          "post",
          "http://example.com/request",
          params,
          oauth,
          tokenSecret
        );
        expect(signature).to.equal("r6/TJjbCOr97/+UU0NsvSne7s5g=");
      });

      it("handles array param with same value", () => {
        const client = new OAuth.Client({
          clientId: "9djdj82h48djs9d2",
          clientSecret: "j49sk3j29djd",
          provider: Bell.providers.twitter(),
        });
        const tokenSecret = "dh893hdasih9";

        const params = {
          b5: "=%3D",
          a3: ["a", "a"],
          "c@": "",
          a2: "r b",
          c2: "",
        };

        const oauth = {
          oauth_consumer_key: "9djdj82h48djs9d2",
          oauth_token: "kkk9d7dh3k39sjv7",
          oauth_signature_method: "HMAC-SHA1",
          oauth_timestamp: "137131201",
          oauth_nonce: "7d8f3e4a",
        };

        const signature = client.signature(
          "post",
          "http://example.com/request",
          params,
          oauth,
          tokenSecret
        );
        expect(signature).to.equal("dub5m7j8nN7KtHBochesFDQHea4=");
      });
    });

    describe("queryString()", () => {
      it("handles params with non-string values", () => {
        const params = {
          a: [1, 2],
          b: null,
          c: [true, false],
          d: Infinity,
        };

        expect(OAuth.Client.queryString(params)).to.equal(
          "a=1&a=2&b=&c=true&c=false&d="
        );
      });
    });
  });
});
