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

function hex(arr) {
  return Array.prototype.map.call(arr, function (byte) {
    return byte.toString(16);
  }).join('');
}

function hex64(arr) {
  return Array.prototype.map.call(arr, function (byte) {
    return '0x'+byte.toString(16);
  }).join(', ');
}

var Dealer = function () {

};

Dealer.dealShares = function (secret, threshold, playerCount) {
  var coeffs = new Float64Array(threshold * 16),
      shares = new Uint8Array(playerCount * 32);

  unpack25519(coeffs, secret);

  // Generate t random coefficients
  var coeff = new Uint8Array(32);
  for(var i = 1; i < threshold; i++){
    randombytes(coeff, 32);
    unpack25519(coeffs.subarray(i*16), coeff);
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

  // Calculate the signature
  for (i = 0; i < 64; i++) x[i] = 0;
  for (i = 0; i < 32; i++) x[i] = ephemeralShare[i];
  for (i = 0; i < 32; i++) {
    for (j = 0; j < 32; j++) {
      x[i+j] += h[i] * share[j];
    }
  }

  modL(signature, x);
}

function signWithPlayers(signatures, players, message, shares, ephemeralShares, publicKey, ephemeralPublicKey) {
  players.forEach(function (i) {
    signWithShare(signatures.subarray((i-1)*32), message, shares.subarray((i-1)*32), ephemeralShares.subarray((i-1)*32),
                  publicKey, ephemeralPublicKey);
  });
}

// A secret is shared among 7 players, four are needed to sign
var keyPair = nacl.sign.keyPair();
var publicKey = keyPair.publicKey;
var secretKey = keyPair.secretKey;
console.log("Secret:", hex(secretKey.subarray(0, 32)));
var shares = Dealer.dealShares(secretKey, 4, 7);
//Dealer.combineShares(7, [1, 3, 5, 6], [shares, shares.subarray((3-1) * 32), shares.subarray((5-1) * 32), shares.subarray((6-1) * 32)]);

// Players 1, 2, 3, 4, 5, 6, 7 want to sign a message. First they create a
// shared secret...
var ephemeralKeyPair = nacl.sign.keyPair();
var ephemeralPublicKey = ephemeralKeyPair.publicKey;
var ephemeralSecretKey = ephemeralKeyPair.secretKey;
var ephemeralShares = Dealer.dealShares(ephemeralSecretKey, 4, 7);


var message = stringToUint("Hello world!");
var signatures = new Uint8Array(32 * 7);
signWithPlayers(signatures, [1, 2, 3, 4, 5, 6, 7], message, shares, ephemeralShares, publicKey, ephemeralPublicKey);
console.log("Signatures", signatures);

// Combine signatures
var signatureSigma = Dealer.combineShares(7, [1, 3, 5, 6], [signatures, signatures.subarray((3-1) * 32), shares.subarray((5-1) * 32), shares.subarray((6-1) * 32)]);
var signature = new Uint8Array(64);
for (i = 0; i < 32; i++) signature[i] = ephemeralPublicKey[i];
for (i = 0; i < 32; i++) signature[32 + i] = signatureSigma[i];
console.log(nacl.sign.detached.verify(message, signature, publicKey));
