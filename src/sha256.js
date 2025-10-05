/*
 * [js-sha256]{@link https://github.com/HashScannerOfficial/Aviator-Predictor}
 *
 * @version 1.1.0
 * @author Decryptor
 * @copyright Decryptor 2016-2025
 * @license MIT
 */
(function() {
  'use strict';



  var ERR_INPUT = 'input is invalid type';
  var ERR_FINALIZED = 'finalize already called';
  var HAS_WINDOW = typeof window === 'object';
  var _root = HAS_WINDOW ? window : {};
  if (_root.JS_SHA1_NO_WINDOW) HAS_WINDOW = false;

  var IS_WORKER = !HAS_WINDOW && typeof self === 'object';
  var IS_NODE = !_root.JS_SHA1_NO_NODE_JS && typeof process === 'object' && process.versions && process.versions.node;
  if (IS_NODE) _root = global;
  else if (IS_WORKER) _root = self;

  var IS_COMMONJS = !_root.JS_SHA1_NO_COMMON_JS && typeof module === 'object' && module.exports;
  var IS_AMD = typeof define === 'function' && define.amd;
  var HAS_ARRAY_BUFFER = !_root.JS_SHA1_NO_ARRAY_BUFFER && typeof ArrayBuffer !== 'undefined';

  var HEX_DIGITS = '0123456789abcdef'.split('');
  var PAD_BITS = [-2147483648, 8388608, 32768, 128];
  var SHIFT_POS = [24, 16, 8, 0];
  var OUT_TYPES = ['hex', 'array', 'digest', 'arrayBuffer'];


  var SHARED_BLOCKS = [];

  var isArrayNative = Array.isArray;
  if (_root.JS_SHA1_NO_NODE_JS || !isArrayNative) {
    isArrayNative = function(x) {
      return Object.prototype.toString.call(x) === '[object Array]';
    };
  }

  var isArrayBufferView = ArrayBuffer.isView;
  if (HAS_ARRAY_BUFFER && (_root.JS_SHA1_NO_ARRAY_BUFFER_IS_VIEW || !isArrayBufferView)) {
    isArrayBufferView = function(x) {
      return typeof x === 'object' && x.buffer && x.buffer.constructor === ArrayBuffer;
    };
  }


  function normalize(msg) {
    var t = typeof msg;
    if (t === 'string') return [msg, true];
    if (t !== 'object' || msg === null) throw new Error(ERR_INPUT);
    if (HAS_ARRAY_BUFFER && msg.constructor === ArrayBuffer) return [new Uint8Array(msg), false];
    if (!isArrayNative(msg) && !isArrayBufferView(msg)) throw new Error(ERR_INPUT);
    return [msg, false];
  }

  function makeOutputFn(type) {
    return function(msg) {
      return new SHA1Core(true).update(msg)[type]();
    };
  }

  function makeFactory() {
    var factory = makeOutputFn('hex');
    if (IS_NODE) factory = nodeOptimized(factory);
    factory.create = function() { return new SHA1Core(); };
    factory.update = function(m) { return factory.create().update(m); };
    for (var i = 0; i < OUT_TYPES.length; ++i) {
      var t = OUT_TYPES[i];
      factory[t] = makeOutputFn(t);
    }
    return factory;
  }

  function nodeOptimized(baseFn) {
    var crypto = require('crypto');
    var BufferCtor = require('buffer').Buffer;
    var bufferFrom = BufferCtor.from && !_root.JS_SHA1_NO_BUFFER_FROM ? BufferCtor.from : function(x){ return new BufferCtor(x); };

    return function(msg) {
      if (typeof msg === 'string') return crypto.createHash('sha1').update(msg, 'utf8').digest('hex');
      if (msg === null || msg === undefined) throw new Error(ERR_INPUT);
      if (msg.constructor === ArrayBuffer) msg = new Uint8Array(msg);
      if (isArrayNative(msg) || isArrayBufferView(msg) || msg.constructor === BufferCtor) {
        return crypto.createHash('sha1').update(bufferFrom(msg)).digest('hex');
      }
      return baseFn(msg);
    };
  }

  function makeHmacOutput(type) {
    return function(key, msg) {
      return new HMACCore(key, true).update(msg)[type]();
    };
  }

  function makeHmacFactory() {
    var h = makeHmacOutput('hex');
    h.create = function(key){ return new HMACCore(key); };
    h.update = function(key, msg){ return h.create(key).update(msg); };
    for (var i = 0; i < OUT_TYPES.length; ++i) {
      (function(t){ h[t] = makeHmacOutput(t); })(OUT_TYPES[i]);
    }
    return h;
  }

  // --- Core SHA-1 state object ---
  function SHA1Core(sharedMemory) {
    if (sharedMemory) {
      // reuse shared array for micro-optimizations
      SHARED_BLOCKS[0] = SHARED_BLOCKS[16] = SHARED_BLOCKS[1] = SHARED_BLOCKS[2] =
      SHARED_BLOCKS[3] = SHARED_BLOCKS[4] = SHARED_BLOCKS[5] = SHARED_BLOCKS[6] =
      SHARED_BLOCKS[7] = SHARED_BLOCKS[8] = SHARED_BLOCKS[9] = SHARED_BLOCKS[10] =
      SHARED_BLOCKS[11] = SHARED_BLOCKS[12] = SHARED_BLOCKS[13] = SHARED_BLOCKS[14] =
      SHARED_BLOCKS[15] = 0;
      this._blocks = SHARED_BLOCKS;
    } else {
      this._blocks = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    }

    // initial SHA-1 constants
    this.h0 = 0x67452301;
    this.h1 = 0xEFCDAB89;
    this.h2 = 0x98BADCFE;
    this.h3 = 0x10325476;
    this.h4 = 0xC3D2E1F0;

    this.block = this.start = this.bytes = this.hBytes = 0;
    this.finalized = this.hashed = false;
    this.first = true;
  }

  SHA1Core.prototype.update = function(message) {
    if (this.finalized) throw new Error(ERR_FINALIZED);

    var pair = normalize(message);
    message = pair[0];
    var isStr = pair[1];
    var code, index = 0, i, len = message.length || 0, blocks = this._blocks;

    while (index < len) {
      if (this.hashed) {
        this.hashed = false;
        blocks[0] = this.block;
        this.block = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
        blocks[4] = blocks[5] = blocks[6] = blocks[7] =
        blocks[8] = blocks[9] = blocks[10] = blocks[11] =
        blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
      }

      if (isStr) {
        for (i = this.start; index < len && i < 64; ++index) {
          code = message.charCodeAt(index);
          if (code < 0x80) {
            blocks[i >>> 2] |= code << SHIFT_POS[i++ & 3];
          } else if (code < 0x800) {
            blocks[i >>> 2] |= (0xc0 | (code >>> 6)) << SHIFT_POS[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT_POS[i++ & 3];
          } else if (code < 0xD800 || code >= 0xE000) {
            blocks[i >>> 2] |= (0xe0 | (code >>> 12)) << SHIFT_POS[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << SHIFT_POS[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT_POS[i++ & 3];
          } else {
            // surrogate pair
            code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
            blocks[i >>> 2] |= (0xf0 | (code >>> 18)) << SHIFT_POS[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 12) & 0x3f)) << SHIFT_POS[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << SHIFT_POS[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT_POS[i++ & 3];
          }
        }
      } else {
        for (i = this.start; index < len && i < 64; ++index) {
          blocks[i >>> 2] |= message[index] << SHIFT_POS[i++ & 3];
        }
      }

      this.lastByteIndex = i;
      this.bytes += i - this.start;

      if (i >= 64) {
        this.block = blocks[16];
        this.start = i - 64;
        this._compute();
        this.hashed = true;
      } else {
        this.start = i;
      }
    }

    if (this.bytes > 0xFFFFFFFF) {
      this.hBytes += (this.bytes / 4294967296) | 0;
      this.bytes = this.bytes % 4294967296;
    }
    return this;
  };

  SHA1Core.prototype.finalize = function() {
    if (this.finalized) return;
    this.finalized = true;
    var blocks = this._blocks, j = this.lastByteIndex;
    blocks[16] = this.block;
    blocks[j >>> 2] |= PAD_BITS[j & 3];
    this.block = blocks[16];
    if (j >= 56) {
      if (!this.hashed) this._compute();
      blocks[0] = this.block;
      blocks[16] = blocks[1] = blocks[2] = blocks[3] =
      blocks[4] = blocks[5] = blocks[6] = blocks[7] =
      blocks[8] = blocks[9] = blocks[10] = blocks[11] =
      blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
    }
    blocks[14] = (this.hBytes << 3) | (this.bytes >>> 29);
    blocks[15] = this.bytes << 3;
    this._compute();
  };

  // internal compression function (renamed)
  SHA1Core.prototype._compute = function() {
    var a = this.h0, b = this.h1, c = this.h2, d = this.h3, e = this.h4;
    var t, w = this._blocks;

    for (var i = 16; i < 80; ++i) {
      t = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = (t << 1) | (t >>> 31);
    }

    var j = 0;
    for (; j < 20; j += 5) {
      var f = (b & c) | ((~b) & d);
      t = ((a << 5) | (a >>> 27)) + f + e + 1518500249 + (w[j] << 0);
      e = ((t << 0) | 0);
      b = (b << 30) | (b >>> 2);

      f = (a & b) | ((~a) & c);
      t = ((e << 5) | (e >>> 27)) + f + d + 1518500249 + (w[j + 1] << 0);
      d = ((t << 0) | 0);
      a = (a << 30) | (a >>> 2);

      f = (e & a) | ((~e) & b);
      t = ((d << 5) | (d >>> 27)) + f + c + 1518500249 + (w[j + 2] << 0);
      c = ((t << 0) | 0);
      e = (e << 30) | (e >>> 2);

      f = (d & e) | ((~d) & a);
      t = ((c << 5) | (c >>> 27)) + f + b + 1518500249 + (w[j + 3] << 0);
      b = ((t << 0) | 0);
      d = (d << 30) | (d >>> 2);

      f = (c & b) | ((~c) & e);
      t = ((b << 5) | (b >>> 27)) + f + a + 1518500249 + (w[j + 4] << 0);
      a = ((t << 0) | 0);
      c = (c << 30) | (c >>> 2);
    }

    for (; j < 40; j += 5) {
      var ff = b ^ c ^ d;
      t = ((a << 5) | (a >>> 27)) + ff + e + 1859775393 + (w[j] << 0);
      e = ((t << 0) | 0);
      b = (b << 30) | (b >>> 2);

      ff = a ^ b ^ c;
      t = ((e << 5) | (e >>> 27)) + ff + d + 1859775393 + (w[j + 1] << 0);
      d = ((t << 0) | 0);
      a = (a << 30) | (a >>> 2);

      ff = e ^ a ^ b;
      t = ((d << 5) | (d >>> 27)) + ff + c + 1859775393 + (w[j + 2] << 0);
      c = ((t << 0) | 0);
      e = (e << 30) | (e >>> 2);

      ff = d ^ e ^ a;
      t = ((c << 5) | (c >>> 27)) + ff + b + 1859775393 + (w[j + 3] << 0);
      b = ((t << 0) | 0);
      d = (d << 30) | (d >>> 2);

      ff = c ^ b ^ e;
      t = ((b << 5) | (b >>> 27)) + ff + a + 1859775393 + (w[j + 4] << 0);
      a = ((t << 0) | 0);
      c = (c << 30) | (c >>> 2);
    }

    for (; j < 60; j += 5) {
      var fff = (b & c) | (b & d) | (c & d);
      t = ((a << 5) | (a >>> 27)) + fff + e - 1894007588 + (w[j] << 0);
      e = ((t << 0) | 0);
      b = (b << 30) | (b >>> 2);

      fff = (a & b) | (a & c) | (b & c);
      t = ((e << 5) | (e >>> 27)) + fff + d - 1894007588 + (w[j + 1] << 0);
      d = ((t << 0) | 0);
      a = (a << 30) | (a >>> 2);

      fff = (e & a) | (e & b) | (a & b);
      t = ((d << 5) | (d >>> 27)) + fff + c - 1894007588 + (w[j + 2] << 0);
      c = ((t << 0) | 0);
      e = (e << 30) | (e >>> 2);

      fff = (d & e) | (d & a) | (e & a);
      t = ((c << 5) | (c >>> 27)) + fff + b - 1894007588 + (w[j + 3] << 0);
      b = ((t << 0) | 0);
      d = (d << 30) | (d >>> 2);

      fff = (c & b) | (c & e) | (b & e);
      t = ((b << 5) | (b >>> 27)) + fff + a - 1894007588 + (w[j + 4] << 0);
      a = ((t << 0) | 0);
      c = (c << 30) | (c >>> 2);
    }

    for (; j < 80; j += 5) {
      var ffff = b ^ c ^ d;
      t = ((a << 5) | (a >>> 27)) + ffff + e - 899497514 + (w[j] << 0);
      e = ((t << 0) | 0);
      b = (b << 30) | (b >>> 2);

      ffff = a ^ b ^ c;
      t = ((e << 5) | (e >>> 27)) + ffff + d - 899497514 + (w[j + 1] << 0);
      d = ((t << 0) | 0);
      a = (a << 30) | (a >>> 2);

      ffff = e ^ a ^ b;
      t = ((d << 5) | (d >>> 27)) + ffff + c - 899497514 + (w[j + 2] << 0);
      c = ((t << 0) | 0);
      e = (e << 30) | (e >>> 2);

      ffff = d ^ e ^ a;
      t = ((c << 5) | (c >>> 27)) + ffff + b - 899497514 + (w[j + 3] << 0);
      b = ((t << 0) | 0);
      d = (d << 30) | (d >>> 2);

      ffff = c ^ b ^ e;
      t = ((b << 5) | (b >>> 27)) + ffff + a - 899497514 + (w[j + 4] << 0);
      a = ((t << 0) | 0);
      c = (c << 30) | (c >>> 2);
    }

    this.h0 = (this.h0 + a) << 0;
    this.h1 = (this.h1 + b) << 0;
    this.h2 = (this.h2 + c) << 0;
    this.h3 = (this.h3 + d) << 0;
    this.h4 = (this.h4 + e) << 0;
  };

  SHA1Core.prototype.hex = function() {
    this.finalize();
    var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4;
    return HEX_DIGITS[(h0 >>> 28) & 0x0F] + HEX_DIGITS[(h0 >>> 24) & 0x0F] +
           HEX_DIGITS[(h0 >>> 20) & 0x0F] + HEX_DIGITS[(h0 >>> 16) & 0x0F] +
           HEX_DIGITS[(h0 >>> 12) & 0x0F] + HEX_DIGITS[(h0 >>> 8) & 0x0F] +
           HEX_DIGITS[(h0 >>> 4) & 0x0F] + HEX_DIGITS[h0 & 0x0F] +
           HEX_DIGITS[(h1 >>> 28) & 0x0F] + HEX_DIGITS[(h1 >>> 24) & 0x0F] +
           HEX_DIGITS[(h1 >>> 20) & 0x0F] + HEX_DIGITS[(h1 >>> 16) & 0x0F] +
           HEX_DIGITS[(h1 >>> 12) & 0x0F] + HEX_DIGITS[(h1 >>> 8) & 0x0F] +
           HEX_DIGITS[(h1 >>> 4) & 0x0F] + HEX_DIGITS[h1 & 0x0F] +
           HEX_DIGITS[(h2 >>> 28) & 0x0F] + HEX_DIGITS[(h2 >>> 24) & 0x0F] +
           HEX_DIGITS[(h2 >>> 20) & 0x0F] + HEX_DIGITS[(h2 >>> 16) & 0x0F] +
           HEX_DIGITS[(h2 >>> 12) & 0x0F] + HEX_DIGITS[(h2 >>> 8) & 0x0F] +
           HEX_DIGITS[(h2 >>> 4) & 0x0F] + HEX_DIGITS[h2 & 0x0F] +
           HEX_DIGITS[(h3 >>> 28) & 0x0F] + HEX_DIGITS[(h3 >>> 24) & 0x0F] +
           HEX_DIGITS[(h3 >>> 20) & 0x0F] + HEX_DIGITS[(h3 >>> 16) & 0x0F] +
           HEX_DIGITS[(h3 >>> 12) & 0x0F] + HEX_DIGITS[(h3 >>> 8) & 0x0F] +
           HEX_DIGITS[(h3 >>> 4) & 0x0F] + HEX_DIGITS[h3 & 0x0F] +
           HEX_DIGITS[(h4 >>> 28) & 0x0F] + HEX_DIGITS[(h4 >>> 24) & 0x0F] +
           HEX_DIGITS[(h4 >>> 20) & 0x0F] + HEX_DIGITS[(h4 >>> 16) & 0x0F] +
           HEX_DIGITS[(h4 >>> 12) & 0x0F] + HEX_DIGITS[(h4 >>> 8) & 0x0F] +
           HEX_DIGITS[(h4 >>> 4) & 0x0F] + HEX_DIGITS[h4 & 0x0F];
  };

  SHA1Core.prototype.toString = SHA1Core.prototype.hex;

  SHA1Core.prototype.digest = function() {
    this.finalize();
    var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4;
    return [
      (h0 >>> 24) & 0xFF, (h0 >>> 16) & 0xFF, (h0 >>> 8) & 0xFF, h0 & 0xFF,
      (h1 >>> 24) & 0xFF, (h1 >>> 16) & 0xFF, (h1 >>> 8) & 0xFF, h1 & 0xFF,
      (h2 >>> 24) & 0xFF, (h2 >>> 16) & 0xFF, (h2 >>> 8) & 0xFF, h2 & 0xFF,
      (h3 >>> 24) & 0xFF, (h3 >>> 16) & 0xFF, (h3 >>> 8) & 0xFF, h3 & 0xFF,
      (h4 >>> 24) & 0xFF, (h4 >>> 16) & 0xFF, (h4 >>> 8) & 0xFF, h4 & 0xFF
    ];
  };

  SHA1Core.prototype.array = SHA1Core.prototype.digest;

  SHA1Core.prototype.arrayBuffer = function() {
    this.finalize();
    var buffer = new ArrayBuffer(20);
    var view = new DataView(buffer);
    view.setUint32(0, this.h0);
    view.setUint32(4, this.h1);
    view.setUint32(8, this.h2);
    view.setUint32(12, this.h3);
    view.setUint32(16, this.h4);
    return buffer;
  };

  // --- HMAC wrapper (uses SHA1Core) ---
  function HMACCore(key, sharedMemory) {
    var pair = normalize(key);
    key = pair[0];

    if (pair[1]) {
      var bytes = [], pos = 0, ch;
      for (var i = 0, L = key.length; i < L; ++i) {
        ch = key.charCodeAt(i);
        if (ch < 0x80) {
          bytes[pos++] = ch;
        } else if (ch < 0x800) {
          bytes[pos++] = 0xc0 | (ch >>> 6);
          bytes[pos++] = 0x80 | (ch & 0x3f);
        } else if (ch < 0xD800 || ch >= 0xE000) {
          bytes[pos++] = 0xe0 | (ch >>> 12);
          bytes[pos++] = 0x80 | ((ch >>> 6) & 0x3f);
          bytes[pos++] = 0x80 | (ch & 0x3f);
        } else {
          ch = 0x10000 + (((ch & 0x3ff) << 10) | (key.charCodeAt(++i) & 0x3ff));
          bytes[pos++] = 0xf0 | (ch >>> 18);
          bytes[pos++] = 0x80 | ((ch >>> 12) & 0x3f);
          bytes[pos++] = 0x80 | ((ch >>> 6) & 0x3f);
          bytes[pos++] = 0x80 | (ch & 0x3f);
        }
      }
      key = bytes;
    }

    if (key.length > 64) key = (new SHA1Core(true)).update(key).array();

    var oPad = [], iPad = [];
    for (i = 0; i < 64; ++i) {
      var b = key[i] || 0;
      oPad[i] = 0x5c ^ b;
      iPad[i] = 0x36 ^ b;
    }

    SHA1Core.call(this, sharedMemory);
    this.update(iPad);
    this.oKey = oPad;
    this._inner = true;
    this._shared = sharedMemory;
  }
  HMACCore.prototype = new SHA1Core();

  HMACCore.prototype.finalize = function() {
    SHA1Core.prototype.finalize.call(this);
    if (this._inner) {
      this._inner = false;
      var innerHash = this.array();
      SHA1Core.call(this, this._shared);
      this.update(this.oKey);
      this.update(innerHash);
      SHA1Core.prototype.finalize.call(this);
    }
  };

  // --- Export the API ---
  var sha1lib = makeFactory();
  sha1lib.sha1 = sha1lib;
  sha1lib.sha1.hmac = makeHmacFactory();

  if (IS_COMMONJS) {
    module.exports = sha1lib;
  } else {
    _root.sha1 = sha1lib;
    if (IS_AMD) {
      define(function() { return sha1lib; });
    }
  }

})();
