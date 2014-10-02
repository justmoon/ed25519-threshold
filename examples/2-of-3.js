var sjcl = require('./sjcl');
var fs = require('fs');
var path = require('path');
var btoa = require('btoa');
var body = fs.readFileSync(path.resolve(__dirname, 'nacl-exposed.js'), {encoding:'utf8'});
eval.call(global, body);

var X2 = gf([0x4a40, 0xdb3a, 0x2f2a, 0x6b99, 0xafb7, 0x82a1, 0xdc19, 0x38ab, 0x4cbb, 0x3237, 0x85e5, 0xf785, 0xcc84, 0xa81b, 0xc1da, 0x106e]),
    Y2 = gf([0x8c84, 0x4370, 0xeab4, 0x2ddb, 0xc43f, 0xc544, 0xde8, 0xada4, 0x4773, 0x23f1, 0xf746, 0xc28c, 0xa097, 0x750f, 0x846b, 0x223a]);


//var keypair = nacl.sign.keyPair();
//var test = [gf(), gf(), gf(), gf()];
//unpackneg(test, keypair.publicKey);
//console.log('var X2 = gf(['+hex64(test[0])+'])');
//console.log('var Y2 = gf(['+hex64(test[1])+'])');
//console.log('var Z2 = gf(['+hex64(test[2])+'])');
//console.log('var T2 = gf(['+hex64(test[3])+'])');

function scalarbase2(p, s) {
  var q = [gf(), gf(), gf(), gf()];
  set25519(q[0], X2);
  set25519(q[1], Y2);
  set25519(q[2], gf1);
  M(q[3], X, Y);
  scalarmult(p, q, s);
}

function bin(arr) {
  return Array.prototype.map.call(arr, function (byte) {
    var byte = byte.toString(2);
    while (byte.length < 8) byte = "0"+byte;
    return byte;
  }).join('');
}

function hex(arr) {
  return Array.prototype.map.call(arr, function (byte) {
    var byte = byte.toString(16);
    return (byte.length < 2) ? "0"+byte : byte;
  }).reverse().join('');
}

function hex64(arr) {
  return Array.prototype.map.call(arr, function (byte) {
    return '0x'+byte.toString(16);
  }).join(', ');
}

function u8ToBn(arr) {
  var bits = sjcl.codec.bytes.toBits(Array.prototype.slice.call(arr).reverse());
  return sjcl.bn.fromBits(bits);
}

function bnToU8(bn) {
  var bits = bn.toBits();
  return new Uint8Array(sjcl.codec.bytes.fromBits(bits).reverse());
}

function hexToBn(str) {
  var bits = sjcl.codec.hex.toBits(str);
  return sjcl.bn.fromBits(bits);
}

var Dealer = function () {

};

Dealer.dealShares = function (secret, threshold, playerCount) {
  var coeffs = [],
      shares = new Uint8Array(playerCount * 32);

  coeffs[0] = u8ToBn(secret);

  // Generate t random coefficients
  for(var i = 1; i < threshold; i++){
    coeffs[i] = sjcl.bn.random(bnL, 0);
  }

  // Calculate shares
  var share;
  for (i = 1; i <= playerCount; i++) {
    share = coeffs[threshold-1];
    for (var j = threshold-2; j >= 0; j--) {
      share = share.mul(i).add(coeffs[j]);
    }
    share = bnToU8(share.mod(bnL));
    for (j = 0; j < 32; j++) {
      shares[(i-1)*32+j] = share[j];
    }
  }

  console.log("Shares\n" + hex(shares).replace(/(.{64})(?!$)/g, '$1\n'));

  return shares;
};

function factorial(num) {
  var value = 1;
  for (var i = 2; i <= num; i++)
    value *= i;
  return value;
}

function calcOmega(playerX, players, delta) {
  var result = delta;

  for (var i = 0, l = players.length; i < l; i++) {
    if (players[i] !== playerX) {
      result *= players[i];
    }
  }

  for (var i = 0, l = players.length; i < l; i++) {
    if (players[i] !== playerX) {
      result /= players[i] - playerX;
    }
  }

  return result;
}

Dealer.combineShares = function (playerCount, players, shares, modulus) {
  var delta = factorial(playerCount);

  if (!modulus) modulus = hexToBn('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed');

  var secret = new sjcl.bn(0);
  for (var i = 0; i < players.length; i++) {
    var omega = calcOmega(players[i], players, delta);
    var share = u8ToBn(shares[i].subarray(0, 32)).mulmod(new sjcl.bn(omega), modulus);
    secret.addM(share);
  }

  var deltaInv = new sjcl.bn(delta).inverseMod(modulus);
  secret = secret.mulmod(deltaInv, modulus);

  return bnToU8(secret);
};

function stringToUint(string) {
    var string = btoa(unescape(encodeURIComponent(string))),
        charList = string.split(''),
        uintArray = [];
    for (var i = 0; i < charList.length; i++) {
        uintArray.push(charList[i].charCodeAt(0));
    }
    return new Uint8Array(uintArray);
}

var hashStorage;
function signWithShare(signature, message, share, ephemeralShare, publicKey, ephemeralPublicKey) {
  var d = new Uint8Array(64), h = new Uint8Array(64), r = new Uint8Array(64);
  var i, j, x = new Float64Array(64);
  var p = [gf(), gf(), gf(), gf()];

  // Copy the message and the seed into signature

  // Pack the point corresponding to the secret seed into signature
  pack(signature, p);

  // Hash the point, public key and message
  var hashBufferLen = message.length + 64;
  var hashBuffer = new Uint8Array(hashBufferLen);
  for (i = 0; i < 32; i++) hashBuffer[i] = ephemeralPublicKey[i];
  for (i = 0; i < 32; i++) hashBuffer[32 + i] = publicKey[i];
  for (i = 0; i < message.length; i++) hashBuffer[64 + i] = message[i];
  crypto_hash(h, hashBuffer, message.length + 64);
  reduce(h);
  hashStorage = h;
  console.log("Hash:", hex(h.subarray(0, 32)));

  // Calculate the signature
  for (i = 0; i < 64; i++) x[i] = 0;
  for (i = 0; i < 32; i++) x[i] = ephemeralShare[i];
  for (i = 0; i < 32; i++) {
    for (j = 0; j < 32; j++) {
      x[i+j] += h[i] * share[j];
    }
  }

  modL(signature, x);

//  var tmp = gf(), tmp2 = gf();
//  unpack25519(tmp, share);
//  unpack25519(tmp2, h);
//  M(tmp, tmp, tmp2);
//  unpack25519(tmp2, ephemeralShare);
//  A(tmp, tmp, tmp2);
//  pack25519(signature, tmp);
//  reduce(signature);
}

function signWithPlayers(signatures, players, message, shares, ephemeralShares, publicKey, ephemeralPublicKey) {
  players.forEach(function (i) {
    signWithShare(signatures.subarray((i-1)*32), message, shares.subarray((i-1)*32), ephemeralShares.subarray((i-1)*32),
                  publicKey, ephemeralPublicKey);
  });
}

function verifySignature(msg, sig, publicKey) {
  checkArrayTypes(msg, sig, publicKey);
  if (sig.length !== crypto_sign_BYTES)
    throw new Error('bad signature size');
  if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
    throw new Error('bad public key size');
  var sm = new Uint8Array(crypto_sign_BYTES + msg.length);
  var m = new Uint8Array(crypto_sign_BYTES + msg.length);
  var i;
  for (i = 0; i < crypto_sign_BYTES; i++) sm[i] = sig[i];
  for (i = 0; i < msg.length; i++) sm[i+crypto_sign_BYTES] = msg[i];
  return (verifySignatureInner(m, sm, sm.length, publicKey) >= 0);
};

function verifySignatureInner(m, sm, n, pk) {
  var i, mlen;
  var t = new Uint8Array(32), h = new Uint8Array(64);
  var p = [gf(), gf(), gf(), gf()],
      q = [gf(), gf(), gf(), gf()];

  mlen = -1;
  if (n < 64) return -1;

  if (unpackneg(q, pk)) return -1;

  for (i = 0; i < n; i++) m[i] = sm[i];
  for (i = 0; i < 32; i++) m[i+32] = pk[i];
  crypto_hash(h, m, n);
  reduce(h);

  // P = hxG
  scalarmult(p, q, h);

  // Q = sigmaG
  scalarbase(q, sm.subarray(32));

  add(p, q);

  // t = eG + hxG - hxG
  pack(t, p);

  // e * G = e * G + hxG - hxG
  n -= 64;
  if (crypto_verify_32(sm, 0, t, 0)) {
    for (i = 0; i < n; i++) m[i] = 0;
    return -1;
  }

  for (i = 0; i < n; i++) m[i] = sm[i + 64];
  mlen = n;
  return mlen;
}

// group order in sjcl-compatible format
var bnL = hexToBn("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

function run() {
  // A secret is shared among 7 players, four are needed to sign
  var secretKey = bnToU8(sjcl.bn.random(bnL, 0));
  var publicKey = new Uint8Array(32);
  var p = [gf(), gf(), gf(), gf()];
  scalarbase(p, secretKey);
  pack(publicKey, p);
  var shares = Dealer.dealShares(secretKey, 2, 3);
  var recombinedSecret = Dealer.combineShares(3, [1, 2], [shares, shares.subarray(32)], bnL);
  console.log("Secret key:       ", hex(secretKey.subarray(0, 32)));
  console.log("Reconstructed key:", hex(recombinedSecret));
  console.log("Public key:", hex(publicKey.subarray(0, 32)));

  // Players 1, 2, 3, 4, 5, 6, 7 want to sign a message. First they create a
  // shared secret...
  var ephemeralSecretKey = bnToU8(sjcl.bn.random(bnL, 0));
  var ephemeralPublicKey = new Uint8Array(32);
  var p = [gf(), gf(), gf(), gf()];
  scalarbase(p, ephemeralSecretKey);
  pack(ephemeralPublicKey, p);
  console.log("Secret ephemeral:", hex(ephemeralSecretKey.subarray(0, 32)));
  console.log("Public ephemeral:", hex(ephemeralPublicKey.subarray(0, 32)));
  var ephemeralShares = Dealer.dealShares(ephemeralSecretKey, 2, 3);


  var message = stringToUint("Hello world!");
  var signatures = new Uint8Array(32 * 2);
  signWithPlayers(signatures, [1, 2], message, shares, ephemeralShares, publicKey, ephemeralPublicKey);
  console.log("Signature shares\n" + hex(signatures).replace(/(.{64})(?!$)/g, '$1\n'));

  // Combine signatures
  var signatureSigma = Dealer.combineShares(3, [1, 2], [signatures, signatures.subarray(32)], bnL);
  console.log("Sigma:         ", hex(signatureSigma));

  var bnSigma = u8ToBn(secretKey).mul(u8ToBn(hashStorage)).add(u8ToBn(ephemeralSecretKey)).mod(bnL);
  var expectedSigma = bnToU8(bnSigma);
  console.log('Expected sigma:', hex(expectedSigma));

  var signature = new Uint8Array(64);
  for (i = 0; i < 32; i++) signature[i] = ephemeralPublicKey[i];
  for (i = 0; i < 32; i++) signature[32 + i] = signatureSigma[i];
  var actualValid = verifySignature(message, signature, publicKey);
  var signedMessage = new Uint8Array(64 + message.length);
  for (i = 0; i < 32; i++) signedMessage[i] = ephemeralPublicKey[i];
  for (i = 0; i < 32; i++) signedMessage[32 + i] = signatureSigma[i];
  for (i = 0; i < message.length; i++) signedMessage[64 + i] = message[i];
  var tweetnaclValid = nacl.sign.open(signedMessage, publicKey);
  console.log("Actual valid:", actualValid);
  console.log("TweetNaCl valid:", !!tweetnaclValid);

  // Poor man's fuzzing
  if (actualValid &&
      tweetnaclValid &&
      hex(secretKey) === hex(recombinedSecret) &&
      hex(signatureSigma) === hex(expectedSigma)) {
    setImmediate(run);
  } else {
    console.log("Invalid!");
    process.exit(0);
  }
}

run();
