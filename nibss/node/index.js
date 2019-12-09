const http = require("http");
const crypto = require("crypto");

var username = "Your organization code";
//Converting organization code to base 64
var organisation_code = Buffer.from(username).toString("base64");
var sandbox_key = "Your sandbox key";

//Data gotten from Reset() headers
let aes_key;
let password;
let ivkey;

//Reset Sandbox Credentials
function Reset() {
  //setting request headers
  var reset_options = {
    
    //change hostname to match Interface URL on innovation sandbox dashboard
    hostname: "",
    path: "/nibss/bvnr/Reset",
    port: 80,
    headers: {
      "Sandbox-Key": sandbox_key,
      OrganisationCode: organisation_code
    },
    method: "POST"
  };

  var data = "";

  callback = function(resp) {
    resp.on("data", chunk => {
      data += chunk;
    });

    resp.on("end", () => {
      console.log(resp.headers);
      aes_key = resp.headers.aes_key;
      password = resp.headers.password;
      ivkey = resp.headers.ivkey;
    });

    resp.on("error", err => {
      console.log("Error: " + err.message);
    });
  };
  const req = http.request(reset_options, callback).end();
}

Reset();

//Encrypt BVN
const encrypt = text => {
  let cipher = crypto.createCipheriv(
    "aes-128-cbc",
    Buffer.from(aes_key),
    ivkey
  );
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return encrypted.toString("hex");
};

//Decrypt Response
const decrypt = text => {
  let textParts = text.split(":");
  let encryptedText = Buffer.from(textParts.join(":"), "hex");
  let decipher = crypto.createDecipheriv(
    "aes-128-cbc",
    Buffer.from(aes_key),
    ivkey
  );
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
};

const date = new Date()
  .toJSON()
  .slice(0, 10)
  .replace(/-/g, "");

//Signing signatureheader(username, currentdate and password) with SHA256
const signatureHeader = crypto
  .createHash("sha256")
  .update(`${username}${date}${password}`)
  .digest("hex");

//Converting to base64
const authHeader = Buffer.from(`${username}:${password}`).toString("base64");
const signatureMethodHeader = "SHA256";
const bvn = "12345678901";
const encrypted = encrypt(`{"BVN": "${bvn}"}`);

//Verify BVN
function BVN() {
  const options = {

    //change hostname to match Interface URL on innovation sandbox dashboard
    hostname: "",
    path: "/nibss/bvnr/VerifySingleBVN",
    port: 80,
    headers: {
      "Sandbox-Key": sandbox_key,
      OrganisationCode: organisation_code,
      Authorization: authHeader,
      SIGNATURE: signatureHeader,
      SIGNATURE_METH: signatureMethodHeader,
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    method: "POST"
  };

  let data = "";

  let decrypted;

  const callback = function(res) {
    res.on("data", chunck => {
      data += chunck;
    });

    //decrepting response
    res.on("end", () => {
      decrypted = decrypt(data);
      console.log(decrypted);
    });

    res.on("error", e => {
      console.log("error", e);
    });
  };

  const req = http
    .request(options, callback)
    .write(encrypted)
    .end();
}

BVN();
