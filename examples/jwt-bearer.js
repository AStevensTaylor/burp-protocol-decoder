// Example custom decoder: shows the claims of a JWT sent as "Authorization: Bearer <jwt>".
// Import it from Protocol Decoder → Decoders → Import… (choose this .js file).

function bearer(msg) {
  var h = msg.requestHeader('Authorization');
  var m = h && /^Bearer\s+([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)$/.exec(h);
  return m ? { header: m[1], payload: m[2], signature: m[3] } : null;
}

function match(msg) {
  // Low confidence so protocol-specific decoders win; use a rule to force it.
  return msg.isRequest && bearer(msg) ? 20 : 0;
}

function decode(msg) {
  var t = bearer(msg);
  if (!t) throw new Error('no Bearer JWT in the Authorization header');
  var header = JSON.parse(codec.utf8Decode(codec.base64Decode(t.header)));
  var claims = JSON.parse(codec.utf8Decode(codec.base64Decode(t.payload)));
  var warnings = [];
  ['iat', 'nbf', 'exp'].forEach(function (k) {
    if (typeof claims[k] === 'number') claims[k] = claims[k] + '  (' + new Date(claims[k] * 1000).toISOString() + ')';
  });
  if (String(header.alg).toLowerCase() === 'none') warnings.push('alg is "none": token is unsigned');
  if (!t.signature) warnings.push('token has no signature part');
  return {
    summary: 'JWT ' + header.alg + (claims.sub ? ' for ' + claims.sub : ''),
    data: { header: header, claims: claims, signatureBytes: codec.base64Decode(t.signature).length },
    warnings: warnings
  };
}
