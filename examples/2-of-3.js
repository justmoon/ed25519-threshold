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
  console.log('var T2 = gf(['+hex64(q[3])+'])');
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

var Dealer = function () {

};

var bloop = 2;
Dealer.dealShares = function (secret, threshold, playerCount) {
  var coeffs = new Float64Array(threshold * 16),
      shares = new Uint8Array(playerCount * 32);

  unpack25519(coeffs, secret);

  // Generate t random coefficients
  var coeff = new Uint8Array(32);
  for(var i = 1; i < threshold; i++){
//    randombytes(coeff, 32);
//    unpack25519(coeffs.subarray(i*16), coeff);
    set25519(coeffs.subarray(i*16), gf([bloop]));
  }

  console.log("Coefficients", coeffs);

  // Calculate shares
  var share;
  for (i = 1; i <= playerCount; i++) {
    share = gf();
    set25519(share, coeffs.subarray((threshold-1) * 16));
    for (var j = threshold-2; j >= 0; j--) {
      M(share, share, gf([i]));
      A(share, share, coeffs.subarray(j*16));
    }
    pack25519(shares.subarray((i-1)*32), share);
  }

  console.log("Shares", shares);

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

Dealer.combineShares = function (playerCount, players, shares) {
  var delta = factorial(playerCount);

  var secret = gf([0]), share = gf();
  for (var i = 0; i < players.length; i++) {
    var omega = calcOmega(players[i], players, delta),
        omegaBig = gf([omega]);
    if (omega < 0) {
      car25519(omegaBig);
    }
    console.log(players[i], omega, omegaBig);
    unpack25519(share, shares[i]);
    M(share, share, omegaBig);
    console.log("term", i, share);
    A(secret, secret, share);
  }

  var deltaInv = gf([delta]);
  inv25519(deltaInv, deltaInv);
  M(secret, secret, deltaInv);

  var secretPacked = new Uint8Array(32);
  pack25519(secretPacked, secret);

  return secretPacked;
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
  crypto_hash(h, hashBuffer.subarray(32), message.length + 32);
  reduce(h);
//  pack25519(h, gf([12]));
  hashStorage = h;
  console.log("Our hash:", hex(h.subarray(0, 32)));

  // Calculate the signature
//  for (i = 0; i < 64; i++) x[i] = 0;
//  for (i = 0; i < 32; i++) x[i] = ephemeralShare[i];
//  for (i = 0; i < 32; i++) {
//    for (j = 0; j < 32; j++) {
//      x[i+j] += h[i] * share[j];
//    }
//  }
//
//  modL(signature, x);

  var tmp = gf(), tmp2 = gf();
  unpack25519(tmp, share);
  unpack25519(tmp2, h);
  M(tmp, tmp, tmp2);
  unpack25519(tmp2, ephemeralShare);
  A(tmp, tmp, tmp2);
  pack25519(signature, tmp);
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
  crypto_hash(h, m.subarray(32), n-32);
  reduce(h);
//  pack25519(h, gf([12]));
  console.log("Their hash:", hex(h.subarray(0, 32)));

  var h25519 = gf();
  var x25519 = gf();
  var hx25519 = gf();
  var hx = new Uint8Array(32);
  var x = new Uint8Array(32);
  unpack25519(h25519, h);
  unpack25519(x25519, secretKey);
  M(hx25519, h25519, x25519);
  pack25519(hx, hx25519);
  pack25519(x, x25519);
  console.log("h =", hex(h.subarray(0, 32)));
  console.log("x =", hex(secretKey));
  console.log("hx =", hex(hx));
  console.log(p);

  // Q_test = xG
  var qTest = [gf(), gf(), gf(), gf()];
  scalarbase(qTest, x);

  var qAsY = new Uint8Array(32);
  pack(qAsY, q);
  console.log("-xG =", hex(qAsY));

  var qTestAsY = new Uint8Array(32);
  pack(qTestAsY, qTest);
  console.log("xG_test =", hex(qTestAsY));

  // P = hxG
  scalarmult(p, q, h);

  // P_test = hxG
  var pTest = [gf(), gf(), gf(), gf()];
  scalarbase(pTest, hx);

  var pAsY = new Uint8Array(32);
  pack(pAsY, p);
  console.log("-hxG =", hex(pAsY));

  var pTestAsY = new Uint8Array(32);
  pack(pTestAsY, pTest);
  console.log("hxG_test =", hex(pTestAsY));

  // Q = sigmaG
  scalarbase(q, sm.subarray(32));

  var qAsY = new Uint8Array(32);
  pack(qAsY, q);
  console.log("sigmaG =", hex(qAsY));

  add(p, q);

  // t = eG + hxG - hxG
  pack(t, p);

  console.log("We have:   "+hex(sm.subarray(0, 32)) + "\n" + "They want: "+hex(t));

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

// A secret is shared among 7 players, four are needed to sign
var keyPair = nacl.sign.keyPair();
//var secretKey = keyPair.secretKey;
//var publicKey = keyPair.publicKey;
var secretKey = new Uint8Array(32);
pack25519(secretKey, gf([3]));
var publicKey = new Uint8Array(32);
var p = [gf(), gf(), gf(), gf()];
scalarbase(p, secretKey);
pack(publicKey, p);
console.log("Secret key:", hex(secretKey.subarray(0, 32)));
console.log("Public key:", hex(publicKey.subarray(0, 32)));
var shares = Dealer.dealShares(secretKey, 2, 3);
var reconstructedSecret = Dealer.combineShares(3, [1, 2], [shares, shares.subarray(32)]);
console.log("Reconstructed secret:", hex(reconstructedSecret));

// Players 1, 2, 3, 4, 5, 6, 7 want to sign a message. First they create a
// shared secret...
var ephemeralKeyPair = nacl.sign.keyPair();
var ephemeralSecretKey = ephemeralKeyPair.secretKey;
//var ephemeralPublicKey = ephemeralKeyPair.publicKey;
//var ephemeralSecretKey = new Uint8Array(32);
//pack25519(ephemeralSecretKey, gf([22]));
var ephemeralPublicKey = new Uint8Array(32);
var p = [gf(), gf(), gf(), gf()];
scalarbase(p, ephemeralSecretKey);
pack(ephemeralPublicKey, p);
console.log("Secret ephemeral:", hex(ephemeralSecretKey.subarray(0, 32)));
console.log("Public ephemeral:", hex(ephemeralPublicKey.subarray(0, 32)));
bloop = 3;
var ephemeralShares = Dealer.dealShares(ephemeralSecretKey, 2, 3);


var message = stringToUint("Hello world6!");
var signatures = new Uint8Array(32 * 2);
signWithPlayers(signatures, [1, 2], message, shares, ephemeralShares, publicKey, ephemeralPublicKey);
console.log("Signatures", signatures);

// Combine signatures
var signatureSigma = Dealer.combineShares(3, [1, 2], [signatures, signatures.subarray(32)]);
console.log("Sigma:         ", hex(signatureSigma));

var expectedSigma = new Uint8Array(32);
var tmp = gf(), tmp2 = gf();
unpack25519(tmp, secretKey);
unpack25519(tmp2, hashStorage);
M(tmp, tmp, tmp2);
unpack25519(tmp2, ephemeralSecretKey);
A(tmp, tmp, tmp2);
pack25519(expectedSigma, tmp);
console.log('Expected sigma:', hex(expectedSigma));

var signature = new Uint8Array(64);
for (i = 0; i < 32; i++) signature[i] = ephemeralPublicKey[i];
for (i = 0; i < 32; i++) signature[32 + i] = signatureSigma[i];
console.log(verifySignature(message, signature, publicKey));
