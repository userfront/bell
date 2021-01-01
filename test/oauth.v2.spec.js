'use strict'

const Crypto = require('crypto')
const sinon = require('sinon')
const nock = require('nock')
const Boom = require('@hapi/boom')
const Code = require('@hapi/code')
const Hapi = require('@hapi/hapi')
const Hoek = require('@hapi/hoek')
const Lab = require('@hapi/lab')

const Bell = require('../lib')
const Mock = require('./mock')

const { describe, it } = (exports.lab = Lab.script())
const { expect } = Code

describe('Bell v2', () => {
  describe('v2()', () => {
    it('authenticates an endpoint with provider parameters', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login')
      expect(res.headers.location).to.contain(
        mock.uri +
          '/auth?special=true&client_id=test&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )
    })

    it('forces https in redirect_uri when set in options', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
        forceHttps: true,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      expect(res1.headers.location).to.contain(
        mock.uri +
          '/auth?special=true&client_id=test&response_type=code&redirect_uri=https%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)
      expect(res2.headers.location).to.contain('https://localhost:8080/login?code=1&state=')

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(200)
    })

    it('uses location setting in redirect_uri when set in options', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
        location: 'https://differenthost:8888',
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      expect(res1.headers.location).to.contain(
        mock.uri +
          '/auth?special=true&client_id=test&response_type=code&redirect_uri=https%3A%2F%2Fdifferenthost%3A8888%2Flogin&state='
      )
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)
      expect(res2.headers.location).to.contain('https://differenthost:8888/login?code=1&state=')

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(200)
    })

    it('ignores empty string returned by location setting (function)', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
        location: () => '',
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login')
      expect(res.headers.location).to.contain(
        mock.uri +
          '/auth?special=true&client_id=test&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )
    })

    it('uses location setting (function) in redirect_uri when set in options', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
        location: request =>
          'https://differenthost:8888' + request.path.replace(/(\/again)?$/, '/again'),
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      server.route({
        method: '*',
        path: '/login/again',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      expect(res1.headers.location).to.contain(
        mock.uri +
          '/auth?special=true&client_id=test&response_type=code&redirect_uri=https%3A%2F%2Fdifferenthost%3A8888%2Flogin%2Fagain&state='
      )
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)
      expect(res2.headers.location).to.contain(
        'https://differenthost:8888/login/again?code=1&state='
      )

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(200)
    })

    it('authenticates an endpoint with custom scope', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        scope: ['a'],
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login')
      expect(res.headers.location).to.contain('scope=a')
    })

    it('authenticates an endpoint with custom function scope', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        scope: request => [request.query.scope],
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login?scope=foo')
      expect(res.headers.location).to.contain('scope=foo')
    })

    it('authenticates with mock Instagram with skip profile', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const custom = Bell.providers.instagram()
      Hoek.merge(custom, mock.provider)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'instagram',
        clientSecret: 'secret',
        provider: custom,
        skipProfile: true,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.result).to.equal({
        provider: 'custom',
        token: '456',
        refreshToken: undefined,
        expiresIn: 3600,
        query: {},
        state: { query: {} },
      })
    })

    it('authenticates an endpoint with runtime query parameters', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
        allowRuntimeProviderParams: true,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login?runtime=5')
      expect(res.headers.location).to.contain(
        mock.uri +
          '/auth?special=true&runtime=5&client_id=test&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )
    })

    it('authenticates an endpoint via oauth with plain PKCE', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const provider = Hoek.merge({ pkce: 'plain' }, mock.provider)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.artifacts
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'
      expect(res1.headers.location).to.contain(
        mock.uri +
          '/auth?client_id=test&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )
      expect(res1.headers.location).to.contain('code_challenge=')
      expect(res1.headers.location).to.contain('code_challenge_method=plain')

      const res2 = await mock.server.inject(res1.headers.location)
      expect(res2.headers.location).to.contain('http://localhost:8080/login?code=1&state=')

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(200)
      expect(res3.result.code_verifier).to.be.a.string()
      expect(res1.headers.location).to.contain(res3.result.code_verifier)
    })

    it('authenticates an endpoint via oauth with S256 PKCE', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const provider = Hoek.merge({ pkce: 'S256' }, mock.provider)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.artifacts
          },
        },
      })

      const res1 = await server.inject('/login?state=something')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'
      expect(res1.headers.location).to.contain(
        mock.uri +
          '/auth?client_id=test&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )
      expect(res1.headers.location).to.contain('code_challenge=')
      expect(res1.headers.location).to.contain('code_challenge_method=S256')

      const res2 = await mock.server.inject(res1.headers.location)
      expect(res2.headers.location).to.contain('http://localhost:8080/login?code=1&state=')

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(200)
      expect(res3.result.code_verifier).to.be.a.string()

      const hash = Crypto.createHash('sha256')
        .update(res3.result.code_verifier, 'ascii')
        .digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')

      expect(res1.headers.location).to.contain(hash)
    })

    it('allows runtime state', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
        runtimeStateCallback: function (request) {
          return request.query.state
        },
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login?state=something')
      expect(res.headers.location).to.contain(
        mock.uri +
          '/auth?special=true&client_id=test&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )
      expect(res.headers.location).to.contain('something')
    })

    it('allows empty or null runtime state', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
        runtimeStateCallback: function (request) {
          return null
        },
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login?state=something')
      expect(res.headers.location).to.contain(
        mock.uri +
          '/auth?special=true&client_id=test&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )
    })

    it('fails on missing state', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'
      expect(res1.headers.location).to.contain(
        mock.uri +
          '/auth?client_id=test&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )

      const res2 = await mock.server.inject(res1.headers.location)
      expect(res2.headers.location).to.contain('http://localhost:8080/login?code=1&state=')

      const res3 = await server.inject({
        url: 'http://localhost:8080/login?code=1',
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(500)
    })

    it('does not include runtime query parameters by default', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login?notallowed=b')
      expect(res.headers.location).to.not.contain('notallowed')
    })

    it('refreshes & errors on missing cookie in token step', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'
      expect(cookie).to.exist()
      expect(res1.headers.location).to.contain(
        mock.uri +
          '/auth?client_id=test&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )

      const res2 = await mock.server.inject(res1.headers.location)
      expect(res2.headers.location).to.contain('http://localhost:8080/login?code=1&state=')

      const res3 = await server.inject(res2.headers.location)
      expect(res3.statusCode).to.equal(200)
      const newLocation = res2.headers.location + '&refresh=1'
      expect(res3.payload).to.contain(newLocation)

      const res4 = await server.inject(newLocation)
      expect(res4.statusCode).to.equal(500)
    })

    it('errors on mismatching state', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'
      expect(res1.headers.location).to.contain(
        mock.uri +
          '/auth?client_id=test&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )

      const res2 = await mock.server.inject(res1.headers.location)
      expect(res2.headers.location).to.contain('http://localhost:8080/login?code=1&state=')

      const res3 = await server.inject({
        url: 'http://localhost:8080/login?code=1&state=xx',
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(500)
    })

    it('errors on failed token request', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const custom = Bell.providers.facebook()
      Hoek.merge(custom, mock.provider)

      Mock.override(mock.provider.token, null)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'facebook',
        clientSecret: 'secret',
        provider: custom,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(500)
    })

    it('errors on errored token request (500)', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const custom = Bell.providers.facebook()
      Hoek.merge(custom, mock.provider)

      Mock.override(mock.provider.token, Boom.badRequest())

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'facebook',
        clientSecret: 'secret',
        provider: custom,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(500)
    })

    it('errors on errored token request (<200)', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const custom = Bell.providers.facebook()
      Hoek.merge(custom, mock.provider)

      const error = Boom.badRequest()
      error.output.statusCode = 199
      Mock.override(mock.provider.token, error)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'facebook',
        clientSecret: 'secret',
        provider: custom,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(500)
    })

    it('errors on invalid token request response', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const custom = Bell.providers.facebook()
      Hoek.merge(custom, mock.provider)

      Mock.override(mock.provider.token, '{x')

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'facebook',
        clientSecret: 'secret',
        provider: custom,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(500)
    })

    it('passes if the client secret is not modified in route', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: Mock.CLIENT_ID_TESTER,
        clientSecret: Mock.CLIENT_SECRET_TESTER,
        provider: mock.provider,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(200)
    })

    it('errors on failed profile request', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const custom = Bell.providers.facebook()
      Hoek.merge(custom, mock.provider)

      Mock.override('https://graph.facebook.com/v3.1/me', null)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'facebook',
        clientSecret: 'secret',
        provider: custom,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(500)
    })

    it('errors on errored profile request', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const custom = Bell.providers.facebook()
      Hoek.merge(custom, mock.provider)

      Mock.override('https://graph.facebook.com/v3.1/me', Boom.badRequest())

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'facebook',
        clientSecret: 'secret',
        provider: custom,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(500)
    })

    it('errors on invalid profile request', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const custom = Bell.providers.facebook()
      Hoek.merge(custom, mock.provider)

      Mock.override('https://graph.facebook.com/v3.1/me', '{c')

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'facebook',
        clientSecret: 'secret',
        provider: custom,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(500)
    })

    it('errors on rejected query parameter', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login?error=access_denied')
      expect(res1.statusCode).to.equal(500)

      const res2 = await server.inject('/login?error=access_denied&error_description="rejection"')
      expect(res2.statusCode).to.equal(500)

      const res3 = await server.inject('/login?denied="definitely"')
      expect(res3.statusCode).to.equal(500)
    })

    it('errors if isSecure is true when protocol is not https', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: true,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: (request, h) => {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login')
      expect(res.statusCode).to.equal(500)
    })

    it('passes if isSecure is true when protocol is https (location)', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: true,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
        location: 'https://differenthost:8888',
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: (request, h) => {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      expect(res1.headers.location).to.contain(
        mock.uri +
          '/auth?special=true&client_id=test&response_type=code&redirect_uri=https%3A%2F%2Fdifferenthost%3A8888%2Flogin&state='
      )
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)
      expect(res2.headers.location).to.contain('https://differenthost:8888/login?code=1&state=')

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(200)
    })

    it('passes if isSecure is true when protocol is https (forced)', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: true,
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
        providerParams: {
          special: true,
        },
        forceHttps: true,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: (request, h) => {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      expect(res1.headers.location).to.contain(
        mock.uri +
          '/auth?special=true&client_id=test&response_type=code&redirect_uri=https%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)
      expect(res2.headers.location).to.contain('https://localhost:8080/login?code=1&state=')

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(200)
    })

    it('passes profile get params', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const custom = Bell.providers.facebook()
      Hoek.merge(custom, mock.provider)

      const override = Mock.override('https://graph.facebook.com/v3.1/me', uri => {
        expect(uri).to.equal(
          'https://graph.facebook.com/v3.1/me?appsecret_proof=d32b1d35fd115c4a496e06fd8df67eed8057688b17140a2cef365cb235817102&fields=id%2Cemail%2Cpicture%2Cname%2Cfirst_name%2Cmiddle_name%2Clast_name%2Clink%2Clocale%2Ctimezone%2Cupdated_time%2Cverified%2Cgender'
        )
      })

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'facebook',
        clientSecret: 'secret',
        provider: custom,
        profileParams: {
          fields:
            'id,email,picture,name,first_name,middle_name,last_name,link,locale,timezone,updated_time,verified,gender',
        },
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)

      await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })

      await override
    })

    it('passes profileParams', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const custom = Bell.providers.facebook()
      Hoek.merge(custom, mock.provider)

      const override = Mock.override('https://graph.facebook.com/v3.1/me', uri => {
        expect(uri).to.equal(
          'https://graph.facebook.com/v3.1/me?appsecret_proof=d32b1d35fd115c4a496e06fd8df67eed8057688b17140a2cef365cb235817102&fields=id%2Cemail%2Cpicture%2Cname%2Cfirst_name%2Cmiddle_name%2Clast_name%2Clink%2Clocale%2Ctimezone%2Cupdated_time%2Cverified%2Cgender'
        )
      })

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'facebook',
        clientSecret: 'secret',
        provider: custom,
        profileParams: {
          fields:
            'id,email,picture,name,first_name,middle_name,last_name,link,locale,timezone,updated_time,verified,gender',
        },
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res1 = await server.inject('/login')
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)

      await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })

      await override
    })
  })

  describe('hooks', () => {
    it('calls preAuthorizationHook if present', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const tenantId = 'abcd1234'
      const clientId = 'test-google-client-id-1234'
      function mockDbLookup(tenantId) {
        return new Promise(resolve => {
          const tenant = {
            name: 'first tenant',
            eid: tenantId,
            googlePublicKey: clientId,
          }
          return resolve(tenant)
        })
      }

      const strategyOptions = {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        preAuthorizationHook: async (request, settings) => {
          const tenant = await mockDbLookup(request.query.tenant_id)
          settings.clientId = tenant.googlePublicKey
        },
        provider: mock.provider,
      }

      const spy = sinon.spy(strategyOptions, 'preAuthorizationHook')

      server.auth.strategy('custom', 'bell', strategyOptions)
      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject(`/login?tenant_id=${tenantId}`)

      // Assert client ID was modified
      expect(res.headers.location).to.contain(
        mock.uri +
          `/auth?client_id=${clientId}&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state=`
      )

      // Assert preAuthorizationHook was called
      expect(spy.calledOnce).to.equal(true)
    })

    it('calls postAuthorizationHook if present', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      const clientId = 'test-google-client-id-1234'
      const clientSecret = 'test-google-client-secret-1234'
      function mockDbLookup(tenantId) {
        return new Promise(resolve => {
          const tenant = {
            name: 'first tenant',
            eid: tenantId,
            googlePublicKey: clientId,
            googlePrivateKey: clientSecret,
          }
          return resolve(tenant)
        })
      }

      const strategyOptions = {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        postAuthorizationHook: async (request, settings) => {
          // Use tenantId from cookie if exists
          if (
            request.state &&
            request.state[settings.cookie] &&
            request.state[settings.cookie].tenant_id
          ) {
            const tenant = await mockDbLookup(request.state[settings.cookie].tenant_id)
            settings.clientId = tenant.googlePublicKey
            settings.clientSecret = tenant.googlePrivateKey
          }
        },
        provider: mock.provider,
      }

      const spy = sinon.spy(strategyOptions, 'postAuthorizationHook')

      server.auth.strategy('custom', 'bell', strategyOptions)
      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const tenantId = 'abcd1234'
      const res1 = await server.inject(`/login?tenant_id=${tenantId}`)
      expect(res1.headers.location).to.contain(
        mock.uri +
          '/auth?client_id=test&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
      )
      const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

      const res2 = await mock.server.inject(res1.headers.location)
      expect(res2.headers.location).to.contain('http://localhost:8080/login?code=1&state=')

      // Mock the POST request that obtains the authorization token
      const url = new URL(res1.headers.location)
      const scope = nock(url.origin)
        .persist()
        .post('/token', body => {
          // Assert clientId & clientSecret were modified
          expect(body.client_id).to.equal(clientId)
          expect(body.client_secret).to.equal(clientSecret)
          return true
        })
        .reply(200)

      const res3 = await server.inject({
        url: res2.headers.location,
        headers: { cookie },
      })
      expect(res3.statusCode).to.equal(200)

      // Assert postAuthorizationHook was called
      expect(spy.calledOnce).to.equal(true)
      expect(scope.pendingMocks()).to.equal([])
    })
  })

  describe('concurrency', () => {
    it('it authenticates 6 requests with same provider', async flags => {
      const mock = await Mock.v2(flags)
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      server.auth.strategy('custom', 'bell', {
        password: 'cookie_encryption_password_secure',
        clientId: 'test',
        clientSecret: 'secret',
        provider: mock.provider,
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'custom',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const arrayOf6 = [...Array(6).keys()]
      const results = await Promise.all(arrayOf6.map(runOAuthFlow))

      for (const requestStates in results) {
        expect(requestStates[0]).to.equal(requestStates[0])
      }

      function runOAuthFlow(n) {
        return new Promise(async resolve => {
          const res1 = await delayedRequest(server, '/login')
          const res1Params = new URLSearchParams(res1.headers.location)

          const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

          const res2 = await delayedRequest(mock.server, res1.headers.location)
          const res2Params = new URLSearchParams(res2.headers.location)

          const res3 = await server.inject({
            url: res2.headers.location,
            headers: { cookie },
          })
          expect(res3.statusCode).to.equal(200)

          return resolve([res1Params.get('state'), res2Params.get('state')])
        })
      }
    })

    it(
      'it authenticates 6 requests. 2 providers, 3 users per provider',
      { plan: 12 },
      async flags => {
        const server = Hapi.server({
          host: 'localhost',
          port: 8080,
        })
        await server.register(Bell)

        // Set up GitHub provider & route
        const githubMock = await Mock.v2(flags, { providerName: 'github' })
        const githubProvider = Bell.providers.github()
        Hoek.merge(githubProvider, githubMock.provider)
        server.auth.strategy('github', 'bell', {
          password: 'cookie_encryption_password_secure',
          isSecure: false,
          clientId: 'github-client-id',
          clientSecret: 'github-client-secret',
          provider: githubProvider,
        })
        server.route({
          method: '*',
          path: '/github-login',
          options: {
            auth: 'github',
            handler: function (request, h) {
              return request.auth.credentials
            },
          },
        })

        // Set up Google provider & route
        const googleMock = await Mock.v2(flags, { providerName: 'google' })
        const googleProvider = Bell.providers.google()
        Hoek.merge(googleProvider, googleMock.provider)
        server.auth.strategy('google', 'bell', {
          password: 'cookie_encryption_password_secure',
          isSecure: false,
          clientId: 'google-client-id',
          clientSecret: 'google-client-secret',
          provider: googleProvider,
        })
        server.route({
          method: '*',
          path: '/google-login',
          options: {
            auth: 'google',
            handler: function (request, h) {
              return request.auth.credentials
            },
          },
        })

        const arrayOf6 = [...Array(6).keys()]
        const results = await Promise.all(arrayOf6.map(runOAuthFlow))

        for (const requestStates in results) {
          expect(requestStates[0]).to.equal(requestStates[0])
        }

        function runOAuthFlow(n) {
          return new Promise(async resolve => {
            const provider = n % 2 === 0 ? 'github' : 'google'
            const mockServer = provider === 'github' ? githubMock.server : googleMock.server

            const res1 = await delayedRequest(server, `/${provider}-login`)
            const res1Params = new URLSearchParams(res1.headers.location)

            const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

            const res2 = await delayedRequest(mockServer, res1.headers.location)
            const res2Params = new URLSearchParams(res2.headers.location)

            Mock.createProviderRequestMock({
              provider,
              type: 'token',
              serverUri: mockServer.info.uri,
            })
            Mock.createProviderRequestMock({
              provider,
              type: 'profile',
            })

            const res3 = await server.inject({
              url: res2.headers.location,
              headers: { cookie },
              validate: false,
            })

            expect(res3.statusCode).to.equal(200)

            return resolve([res1Params.get('state'), res2Params.get('state')])
          })
        }
      }
    )

    it(
      'it authenticates 9 requests. 3 providers, 3 users per provider',
      { plan: 18 },
      async flags => {
        const server = Hapi.server({
          host: 'localhost',
          port: 8080,
        })
        await server.register(Bell)

        // Set up GitHub provider & route
        const githubMock = await Mock.v2(flags, { providerName: 'github' })
        const githubProvider = Bell.providers.github()
        Hoek.merge(githubProvider, githubMock.provider)
        server.auth.strategy('github', 'bell', {
          password: 'cookie_encryption_password_secure',
          isSecure: false,
          clientId: 'github-client-id',
          clientSecret: 'github-client-secret',
          provider: githubProvider,
        })
        server.route({
          method: '*',
          path: '/github-login',
          options: {
            auth: 'github',
            handler: function (request, h) {
              return request.auth.credentials
            },
          },
        })

        // Set up Google provider & route
        const googleMock = await Mock.v2(flags, { providerName: 'google' })
        const googleProvider = Bell.providers.google()
        Hoek.merge(googleProvider, googleMock.provider)
        server.auth.strategy('google', 'bell', {
          password: 'cookie_encryption_password_secure',
          isSecure: false,
          clientId: 'google-client-id',
          clientSecret: 'google-client-secret',
          provider: googleProvider,
        })
        server.route({
          method: '*',
          path: '/google-login',
          options: {
            auth: 'google',
            handler: function (request, h) {
              return request.auth.credentials
            },
          },
        })

        // Set up Azure provider & route
        const azureMock = await Mock.v2(flags, { providerName: 'azure' })
        const azureProvider = Bell.providers.azure()
        Hoek.merge(azureProvider, azureMock.provider)
        server.auth.strategy('azure', 'bell', {
          password: 'cookie_encryption_password_secure',
          isSecure: false,
          clientId: 'azure-client-id',
          clientSecret: 'azure-client-secret',
          provider: azureProvider,
        })
        server.route({
          method: '*',
          path: '/azure-login',
          options: {
            auth: 'azure',
            handler: function (request, h) {
              return request.auth.credentials
            },
          },
        })

        const arrayOf9 = [...Array(9).keys()]
        const results = await Promise.all(arrayOf9.map(runOAuthFlow))

        for (const requestStates in results) {
          expect(requestStates[0]).to.equal(requestStates[0])
        }

        function runOAuthFlow(n) {
          return new Promise(async resolve => {
            let provider
            let mockServer
            // Alternate between each provider based on `n`
            if ([0, 3, 6].includes(n)) {
              provider = 'github'
              mockServer = githubMock.server
            } else if ([1, 4, 7].includes(n)) {
              provider = 'google'
              mockServer = googleMock.server
            } else {
              provider = 'azure'
              mockServer = azureMock.server
            }

            const res1 = await delayedRequest(server, `/${provider}-login`)
            const res1Params = new URLSearchParams(res1.headers.location)

            const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

            const res2 = await delayedRequest(mockServer, res1.headers.location)
            const res2Params = new URLSearchParams(res2.headers.location)

            Mock.createProviderRequestMock({
              provider,
              type: 'token',
              serverUri: mockServer.info.uri,
            })
            Mock.createProviderRequestMock({
              provider,
              type: 'profile',
            })

            const res3 = await server.inject({
              url: res2.headers.location,
              headers: { cookie },
              validate: false,
            })

            expect(res3.statusCode).to.equal(200)

            return resolve([res1Params.get('state'), res2Params.get('state')])
          })
        }
      }
    )

    it('it authenticates 6 requests, all using different providers', async flags => {
      // { plan: 12 },
      const server = Hapi.server({
        host: 'localhost',
        port: 8080,
      })
      await server.register(Bell)

      // Set up Auth0 provider & route
      const auth0Mock = await Mock.v2(flags, { providerName: 'auth0' })
      const auth0Provider = Bell.providers.auth0({ domain: 'example.auth0.com' })
      Hoek.merge(auth0Provider, auth0Mock.provider)
      server.auth.strategy('auth0', 'bell', {
        config: {
          domain: 'example.auth0.com',
        },
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'auth0-client-id',
        clientSecret: 'auth0-client-secret',
        provider: auth0Provider,
      })

      server.route({
        method: '*',
        path: '/auth0-login',
        options: {
          auth: 'auth0',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      // Set up Azure provider & route
      const azureMock = await Mock.v2(flags, { providerName: 'azure' })
      const azureProvider = Bell.providers.azure()
      Hoek.merge(azureProvider, azureMock.provider)
      server.auth.strategy('azure', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'azure-client-id',
        clientSecret: 'azure-client-secret',
        provider: azureProvider,
      })
      server.route({
        method: '*',
        path: '/azure-login',
        options: {
          auth: 'azure',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      // Set up Facebook provider & route
      const facebookMock = await Mock.v2(flags, { providerName: 'facebook' })
      const facebookProvider = Bell.providers.facebook()
      Hoek.merge(facebookProvider, facebookMock.provider)
      server.auth.strategy('facebook', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'facebook-client-id',
        clientSecret: 'facebook-client-secret',
        provider: facebookProvider,
      })
      server.route({
        method: '*',
        path: '/facebook-login',
        options: {
          auth: 'facebook',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      // Set up GitHub provider & route
      const githubMock = await Mock.v2(flags, { providerName: 'github' })
      const githubProvider = Bell.providers.github()
      Hoek.merge(githubProvider, githubMock.provider)
      server.auth.strategy('github', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'github-client-id',
        clientSecret: 'github-client-secret',
        provider: githubProvider,
      })
      server.route({
        method: '*',
        path: '/github-login',
        options: {
          auth: 'github',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      // Set up Google provider & route
      const googleMock = await Mock.v2(flags, { providerName: 'google' })
      const googleProvider = Bell.providers.google()
      Hoek.merge(googleProvider, googleMock.provider)
      server.auth.strategy('google', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'google-client-id',
        clientSecret: 'google-client-secret',
        provider: googleProvider,
      })
      server.route({
        method: '*',
        path: '/google-login',
        options: {
          auth: 'google',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      // Set up LinkedIn provider & route
      const linkedinMock = await Mock.v2(flags, { providerName: 'linkedin' })
      const linkedinProvider = Bell.providers.linkedin()
      Hoek.merge(linkedinProvider, linkedinMock.provider)
      server.auth.strategy('linkedin', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'linkedin-client-id',
        clientSecret: 'linkedin-client-secret',
        provider: linkedinProvider,
      })
      server.route({
        method: '*',
        path: '/linkedin-login',
        options: {
          auth: 'linkedin',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const providerMocks = [
        { name: 'auth0', mock: auth0Mock },
        { name: 'azure', mock: azureMock },
        { name: 'facebook', mock: facebookMock },
        { name: 'github', mock: githubMock },
        { name: 'google', mock: googleMock },
        { name: 'linkedin', mock: linkedinMock },
      ]

      const arrayOf6 = [...Array(6).keys()]
      const results = await Promise.all(arrayOf6.map(runOAuthFlow))

      for (const requestStates in results) {
        expect(requestStates[0]).to.equal(requestStates[0])
      }

      function runOAuthFlow(n) {
        return new Promise(async resolve => {
          // Alternate between each provider based on `n`
          const providerMockObj = providerMocks[n]
          const provider = providerMockObj.name
          const mockServer = providerMockObj.mock.server

          const res1 = await delayedRequest(server, `/${provider}-login`)
          const res1Params = new URLSearchParams(res1.headers.location)

          const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

          const res2 = await delayedRequest(mockServer, res1.headers.location)
          const res2Params = new URLSearchParams(res2.headers.location)

          Mock.createProviderRequestMock({
            provider,
            type: 'token',
            serverUri: mockServer.info.uri,
          })
          Mock.createProviderRequestMock({
            provider,
            type: 'profile',
          })

          const res3 = await server.inject({
            url: res2.headers.location,
            headers: { cookie },
            validate: false,
          })

          expect(res3.statusCode).to.equal(200)

          return resolve([res1Params.get('state'), res2Params.get('state')])
        })
      }
    })

    function delayedRequest(server, url) {
      return new Promise(resolve => {
        // Delay 20-180ms
        const delay = Math.random().toString().slice(2, 3) * 20 || 20

        setTimeout(() => {
          resolve(server.inject(url))
        }, delay)
      })
    }
  })
})
