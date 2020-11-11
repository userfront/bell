'use strict'

const Bell = require('../lib')
const Boom = require('@hapi/boom')
const Code = require('@hapi/code')
const Hapi = require('@hapi/hapi')
const Hoek = require('@hapi/hoek')
const Lab = require('@hapi/lab')

const Constants = require('./constants.json')
const Mock = require('./mock')

const { describe, it } = (exports.lab = Lab.script())
const expect = Code.expect

const privateKey = Constants.privateKey

describe.only('Bell', () => {
  it('authenticates an endpoint via oauth', async flags => {
    const mock = await Mock.v1(flags)
    const server = Hapi.server({ host: 'localhost', port: 8080 })
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

    const res1 = await server.inject('/login?next=%2Fhome')
    const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'
    expect(res1.headers.location).to.equal(mock.uri + '/auth?oauth_token=1')

    const res2 = await mock.server.inject(res1.headers.location)
    expect(res2.headers.location).to.equal(
      'http://localhost:8080/login?oauth_token=1&oauth_verifier=123'
    )

    const res3 = await server.inject({ url: res2.headers.location, headers: { cookie } })
    expect(res3.result.provider).to.equal('custom')
    expect(res3.result.query.next).to.equal('/home')
  })

  it('authenticates an endpoint via oauth using RSA-SHA1 signing', async flags => {
    const mock = await Mock.v1(flags, { signatureMethod: 'RSA-SHA1' })
    const server = Hapi.server({ host: 'localhost', port: 8080 })
    await server.register(Bell)

    server.auth.strategy('custom', 'bell', {
      password: 'cookie_encryption_password_secure',
      isSecure: false,
      clientId: 'test',
      clientSecret: privateKey,
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

    const res1 = await server.inject('/login?next=%2Fhome')
    const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'
    expect(res1.headers.location).to.equal(mock.uri + '/auth?oauth_token=1')

    const res2 = await mock.server.inject(res1.headers.location)
    expect(res2.headers.location).to.equal(
      'http://localhost:8080/login?oauth_token=1&oauth_verifier=123'
    )

    const res3 = await server.inject({ url: res2.headers.location, headers: { cookie } })
    expect(res3.result.provider).to.equal('custom')
    expect(res3.result.query.next).to.equal('/home')
  })

  it.only('authenticates an endpoint via oauth2', async flags => {
    const mock = await Mock.v2(flags)
    const server = Hapi.server({ host: 'localhost', port: 8080 })
    await server.register(Bell)

    server.auth.strategy('custom', 'bell', {
      password: 'cookie_encryption_password_secure',
      isSecure: false,
      clientId: 'test',
      clientSecret: 'secret',
      provider: mock.provider,
    })

    server.route({
      method: 'GET',
      path: '/login',
      options: {
        auth: 'custom',
        handler: function (request, h) {
          return request.auth.credentials
        },
      },
    })

    const res1 = await server.inject('/login')
    // const res1 = await server.inject('/login?tenant_id=abcd1234')
    expect(res1.headers.location).to.contain(
      mock.uri +
        '/auth?client_id=test&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
    )
    const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'

    const res2 = await mock.server.inject(res1.headers.location)
    expect(res2.headers.location).to.contain('http://localhost:8080/login?code=1&state=')

    const res3 = await server.inject({ url: res2.headers.location, headers: { cookie } })
    expect(res3.result.provider).to.equal('custom')
  })

  it('authenticates an endpoint via oauth2 and basic authentication', async flags => {
    const mock = await Mock.v2(flags, { useParamsAuth: false })
    const server = Hapi.server({ host: 'localhost', port: 8080 })
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

    const res3 = await server.inject({ url: res2.headers.location, headers: { cookie } })
    expect(res3.result.provider).to.equal('custom')
  })

  it('authenticates an endpoint via oauth2 with custom client secret options', async flags => {
    const mock = await Mock.v2(flags, false)
    const server = Hapi.server({ host: 'localhost', port: 8080 })
    await server.register(Bell)

    server.auth.strategy('custom', 'bell', {
      password: 'cookie_encryption_password_secure',
      isSecure: false,
      clientId: 'customSecret',
      clientSecret: { headers: { mycustomtoken: 'mycustomtoken' } },
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
        '/auth?client_id=customSecret&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
    )

    const res2 = await mock.server.inject(res1.headers.location)
    expect(res2.headers.location).to.contain('http://localhost:8080/login?code=1&state=')

    const res3 = await server.inject({ url: res2.headers.location, headers: { cookie } })
    expect(res3.result.provider).to.equal('custom')
    expect(res3.result.token).to.equal('mycustomtoken')
  })

  it('authenticates an endpoint via oauth2 with custom client secret options and params auth', async flags => {
    const mock = await Mock.v2(flags, true) // Sets useParamsAuth = true
    const server = Hapi.server({ host: 'localhost', port: 8080 })
    await server.register(Bell)

    server.auth.strategy('custom', 'bell', {
      password: 'cookie_encryption_password_secure',
      isSecure: false,
      clientId: 'customSecret',
      clientSecret: { headers: { mycustomtoken: 'mycustomtoken' } },
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
        '/auth?client_id=customSecret&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state='
    )

    const res2 = await mock.server.inject(res1.headers.location)
    expect(res2.headers.location).to.contain('http://localhost:8080/login?code=1&state=')

    const res3 = await server.inject({ url: res2.headers.location, headers: { cookie } })
    expect(res3.result.provider).to.equal('custom')
    expect(res3.result.token).to.equal('mycustomtoken')
  })

  it('authenticates an endpoint via oauth2 with third party credentials', async flags => {
    const tenantId = 'abcd1234'
    const clientId = 'tenant-1-google-client-id'
    const clientSecret = 'tenant-1-google-client-secret'

    const mock = await Mock.v2(flags, true) // Sets useParamsAuth = true
    const server = Hapi.server({ host: 'localhost', port: 8080 })
    await server.register(Bell)

    server.auth.strategy('custom', 'bell', {
      password: 'cookie_encryption_password_secure',
      isSecure: false,
      clientId: 'customClientId',
      clientSecret: { headers: { mycustomtoken: 'mycustomtoken' } },
      clientFunction: (request, settings) => {
        // console.log(`\nclientFunction request`, request.query)
        // console.log(`clientFunction settings`, settings)

        // If there is no code, we know we're making the first request to the third party
        if (!request.code) {
          // Imitate DB lookup for tenant's client ID & secret
          // const tenant = await Tenant.findOne({ id: request.query.tenant_id })
          const tenant = {
            name: 'tenant 11',
            sso: {
              google: {
                clientId,
                clientSecret,
              },
            },
          }

          // console.log(`0settings`, settings)

          settings.clientId = tenant.sso.google.clientId
          settings.clientSecret = tenant.sso.google.clientSecret
        }

        // console.log(`1settings`, settings)
      },
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

    const res1 = await server.inject(`/login?tenant_id=${tenantId}`)
    const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'
    expect(res1.headers.location).to.contain(
      mock.uri +
        `/auth?client_id=${clientId}&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state=`
    )

    const res2 = await mock.server.inject(res1.headers.location)
    expect(res2.headers.location).to.contain('http://localhost:8080/login?code=1&state=')
    console.log('res2.headers.location', res2.headers.location)

    const res3 = await server.inject({ url: res2.headers.location, headers: { cookie } })
    expect(res3.result.provider).to.equal('custom')
    console.log('res3.result', res3.result)
    expect(res3.result.token).to.equal(clientSecret)
  })

  it('1', async flags => {
    const tenantId = 'abcd1234'
    const clientId = 'tenant-1-google-client-id'
    const clientSecret = 'tenant-1-google-client-secret'

    const mock = await Mock.v2(flags, true) // Sets useParamsAuth = true
    const server = Hapi.server({ host: 'localhost', port: 8080 })
    await server.register(Bell)

    server.auth.strategy('custom', 'bell', {
      password: 'cookie_encryption_password_secure',
      isSecure: false,
      clientId: 'customClientId',
      clientSecret: { headers: { mycustomtoken: 'mycustomtoken' } },
      clientFunction: (request, settings) => {
        console.log(`\nclientFunction request`, request.query)
        // console.log(`clientFunction settings`, settings)

        // console.log(`1settings`, settings)
      },
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

    const res1 = await server.inject(`/login?tenant_id=${tenantId}`)
    const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'
    expect(res1.headers.location).to.contain(
      mock.uri +
        `/auth?client_id=customClientId&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state=`
    )

    const res2 = await mock.server.inject(res1.headers.location)
    expect(res2.headers.location).to.contain('http://localhost:8080/login?code=1&state=')
    console.log('res2.headers.location', res2.headers.location)

    const res3 = await server.inject({ url: res2.headers.location, headers: { cookie } })
    expect(res3.result.provider).to.equal('custom')
    console.log('res3.result', res3.result)
    expect(res3.result.token).to.equal(clientSecret)
  })

  it('2', async flags => {
    const tenantId = 'abcd1234'
    const clientId = 'tenant-1-google-client-id'
    const clientSecret = 'tenant-1-google-client-secret'

    const mock = await Mock.v2(flags, true) // Sets useParamsAuth = true
    const server = Hapi.server({ host: 'localhost', port: 8080 })
    await server.register(Bell)

    server.auth.strategy('custom', 'bell', {
      password: 'cookie_encryption_password_secure',
      isSecure: false,
      clientId: 'customClientId',
      clientSecret: { headers: { mycustomtoken: 'mycustomtoken' } },
      clientFunction: (request, settings) => {
        // console.log(`\nclientFunction request`, request.query)
        // console.log(`clientFunction settings`, settings)

        // If there is no code, we know we're making the first request to the third party
        if (!request.code) {
          // Imitate DB lookup for tenant's client ID & secret
          // const tenant = await Tenant.findOne({ id: request.query.tenant_id })
          const tenant = {
            name: 'tenant 11',
            sso: {
              google: {
                clientId,
                clientSecret,
              },
            },
          }

          // console.log(`0settings`, settings)

          settings.clientId = tenant.sso.google.clientId
          settings.clientSecret = tenant.sso.google.clientSecret
        }

        // console.log(`1settings`, settings)
      },
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

    const res1 = await server.inject(`/login?tenant_id=${tenantId}`)
    const cookie = res1.headers['set-cookie'][0].split(';')[0] + ';'
    expect(res1.headers.location).to.contain(
      mock.uri +
        `/auth?client_id=${clientId}&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin&state=`
    )

    const res2 = await mock.server.inject(res1.headers.location)
    expect(res2.headers.location).to.contain('http://localhost:8080/login?code=1&state=')
    console.log('res2.headers.location', res2.headers.location)

    const res3 = await server.inject({ url: res2.headers.location, headers: { cookie } })
    expect(res3.result.provider).to.equal('custom')
    console.log('res3.result', res3.result)
    expect(res3.result.token).to.equal(clientSecret)
  })

  it('overrides cookie name', async flags => {
    const mock = await Mock.v1(flags)
    const server = Hapi.server({ host: 'localhost', port: 8080 })
    await server.register(Bell)

    server.auth.strategy('custom', 'bell', {
      password: 'cookie_encryption_password_secure',
      isSecure: false,
      clientId: 'test',
      clientSecret: 'secret',
      provider: mock.provider,
      cookie: 'ring',
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
    expect(res.headers['set-cookie'][0]).to.contain('ring=')
  })

  it('allows multiple custom provider names', async flags => {
    const mock = await Mock.v1(flags)
    const server = Hapi.server({ host: 'localhost', port: 8080 })
    await server.register(Bell)

    server.auth.strategy('custom_1', 'bell', {
      password: 'cookie_encryption_password_secure',
      isSecure: false,
      clientId: 'test',
      clientSecret: 'secret',
      provider: Hoek.merge(Hoek.clone(mock.provider), { name: 'custom_1' }),
      cookie: 'ring_1',
    })

    server.auth.strategy('custom_2', 'bell', {
      password: 'cookie_encryption_password_secure',
      isSecure: false,
      clientId: 'test',
      clientSecret: 'secret',
      provider: Hoek.merge(Hoek.clone(mock.provider), { name: 'custom_2' }),
      cookie: 'ring_2',
    })

    server.route({
      method: '*',
      path: '/login_1',
      options: {
        auth: 'custom_1',
        handler: function (request, h) {
          return request.auth.credentials
        },
      },
    })

    server.route({
      method: '*',
      path: '/login_2',
      options: {
        auth: 'custom_2',
        handler: function (request, h) {
          return request.auth.credentials
        },
      },
    })

    const res1 = await server.inject('/login_1')
    expect(res1.headers['set-cookie'][0]).to.contain('ring_1=')

    const res2 = await server.inject('/login_2')
    expect(res2.headers['set-cookie'][0]).to.contain('ring_2=')
  })

  it('exposes OAuth implementation', () => {
    expect(Bell.oauth.Client).to.be.function()
  })

  it('exposes OAuth via plugin', async () => {
    const server = Hapi.server({ host: 'localhost', port: 8080 })
    await server.register(Bell)

    expect(server.plugins.bell.oauth.Client).to.be.function()
  })

  describe('simulate()', () => {
    it('authenticates an endpoint via oauth', async () => {
      Bell.simulate(request => {
        return { some: 'value' }
      })

      const server = Hapi.server()
      await server.register(Bell)

      server.auth.strategy('twitter', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: 'twitter',
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'twitter',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login?next=%2Fhome')
      expect(res.result).to.equal({
        provider: 'twitter',
        token: 'oauth_token',
        query: {
          next: '/home',
        },
        secret: 'token_secret',
        some: 'value',
      })

      Bell.simulate(false)
    })
    it('authenticates an endpoint via oauth', async () => {
      Bell.simulate(request => {
        return { some: 'value' }
      })

      const server = Hapi.server()
      await server.register(Bell)

      server.auth.strategy('twitter', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: 'twitter',
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'twitter',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login?next=%2Fhome')
      expect(res.result).to.equal({
        provider: 'twitter',
        token: 'oauth_token',
        query: {
          next: '/home',
        },
        secret: 'token_secret',
        some: 'value',
      })

      Bell.simulate(false)
    })

    it('authenticates an endpoint via oauth2', async () => {
      Bell.simulate(request => {
        return { some: 'value' }
      })

      const server = Hapi.server()
      await server.register(Bell)

      server.auth.strategy('github', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: 'github',
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'github',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login?next=%2Fhome')
      expect(res.result).to.equal({
        provider: 'github',
        token: 'oauth_token',
        query: {
          next: '/home',
        },
        refreshToken: 'refresh_token',
        expiresIn: 3600,
        some: 'value',
      })

      Bell.simulate(false)
    })

    it('simulates error', async () => {
      Bell.simulate(request => {
        throw Boom.badRequest()
      })

      const server = Hapi.server()
      await server.register(Bell)

      server.auth.strategy('twitter', 'bell', {
        password: 'cookie_encryption_password_secure',
        isSecure: false,
        clientId: 'test',
        clientSecret: 'secret',
        provider: 'twitter',
      })

      server.route({
        method: '*',
        path: '/login',
        options: {
          auth: 'twitter',
          handler: function (request, h) {
            return request.auth.credentials
          },
        },
      })

      const res = await server.inject('/login?next=%2Fhome')
      expect(res.statusCode).to.equal(400)

      Bell.simulate(false)
    })
  })
})
