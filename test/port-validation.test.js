'use strict'

const test = require('tape')
const fastURI = require('..')

test('port serialization rejects non-digit values', (t) => {
  const malformedPorts = [
    '@127.0.0.1:8124',
    '8080@evil.example',
    '8080/path',
    '8080?query',
    '8080#fragment',
    '8080:9000',
    '-1',
    '1.5',
    1.5,
    NaN,
    Infinity,
    '١'
  ]

  for (const port of malformedPorts) {
    t.throws(
      () => fastURI.serialize({ scheme: 'http', host: 'trusted.example', port, path: '/app' }),
      /URI port is malformed\./,
      String(port)
    )
  }

  t.throws(
    () => fastURI.normalize({ scheme: 'http', host: 'trusted.example', port: '@evil.example' }),
    /URI port is malformed\./,
    'object normalization rejects a malformed port'
  )
  t.equal(
    fastURI.equal(
      { scheme: 'http', host: 'trusted.example', port: '@evil.example' },
      { scheme: 'http', host: 'trusted.example', port: '@evil.example' }
    ),
    false,
    'object equality fails closed for a malformed port'
  )
  t.end()
})

test('port serialization preserves RFC 3986 digit values', (t) => {
  const validPorts = [
    [8080, '8080'],
    ['8080', '8080'],
    ['00080', '00080'],
    ['', '']
  ]

  for (const [port, expected] of validPorts) {
    t.equal(
      fastURI.serialize({ scheme: 'uri', host: 'example.test', port }),
      `uri://example.test:${expected}`,
      JSON.stringify(port)
    )
  }
  t.end()
})

test('a port parsed out of a URI string still round-trips', (t) => {
  // parse() only ever yields digits for port, so the guard must not reject
  // anything that came back from a real URI.
  const parsed = fastURI.parse('http://example.test:8080/app')
  t.equal(parsed.port, 8080)
  t.equal(fastURI.serialize(parsed), 'http://example.test:8080/app')
  t.end()
})

test('component resolution rejects a malformed port', (t) => {
  t.throws(
    () => fastURI.resolveComponent(
      { scheme: 'http', host: 'trusted.example', port: '@evil.example', path: '/' },
      { path: 'app' }
    ),
    /URI port is malformed\./,
    'a malformed port on the base component is rejected'
  )

  t.throws(
    () => fastURI.resolveComponent(
      { scheme: 'http', host: 'trusted.example', path: '/' },
      { host: 'trusted.example', port: '8080@evil.example', path: '/app' }
    ),
    /URI port is malformed\./,
    'a malformed port on the relative component is rejected'
  )

  t.equal(
    fastURI.resolveComponent(
      { scheme: 'http', host: 'trusted.example', port: '8080', path: '/' },
      { path: 'app' }
    ).port,
    8080,
    'a digit-only port still resolves'
  )
  t.end()
})
