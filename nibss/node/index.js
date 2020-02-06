const http = require("http");
const crypto = require("crypto");

// Replace with actual credentials
const sandboxKey = "";
const username = ""

// change hostname to match Interface URL on innovation sandbox dashboard
const hostname = "";

// Converting organization code to base 64
const organisationCode = Buffer.from(username).toString("base64");
const crypt = (aesKey, ivKey) => ({
  // Encrypt BVN
  encrypt: (plainText) => {
    const cipher = crypto.createCipheriv("aes-128-cbc", Buffer.from(aesKey), ivKey);
    let encrypted = cipher.update(plainText);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted.toString("hex");
  },
  // Decrypt Response
  decrypt: (text) => {
    const textParts = text.split(":");
    const encryptedText = Buffer.from(textParts.join(":"), "hex");
    const decipher = crypto.createDecipheriv("aes-128-cbc", Buffer.from(aesKey), ivKey);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  },
});

// Reset Sandbox Credentials
async function Reset() {
  let data = "";
  const options = {
    hostname,
    path: "/nibss/bvnr/Reset",
    method: "POST",
    // setting request headers
    headers: {
      "Sandbox-Key": sandboxKey,
      OrganisationCode: organisationCode,
    },
  };

  return new Promise((resolve, reject) => {
    const request = http.request(options, (response) => {
      response.on("error", error => reject(error));

      response.on('data', (chunk) => {
        data += chunk;
      });

      response.on("end", () => resolve({
        aesKey: response.headers.aes_key,
        ivKey: response.headers.ivkey,
        password: response.headers.password,
      }));
    });

    request.on("error", (error) => reject(error));
    request.end();
  });
}

// Verify BVN
async function BVN() {
  try {
    // Data gotten from Reset() headers
    const { aesKey, ivKey, password } = await Reset();
    const cr = crypt(aesKey, ivKey);

    // Signing signatureheader(username, currentdate and password) with SHA256
    const today = new Date().toJSON().slice(0, 10).replace(/-/g, "");
    const signatureHeader = crypto.createHash("sha256").update(`${username}${today}${password}`).digest("hex");
    const authorizationHeader = Buffer.from(`${username}:${password}`).toString("base64");
    const signatureMethodHeader = "SHA256";
    const payload = `{"BVN": "12345678901"}`;
    const encrypted = cr.encrypt(payload);

    console.log("SENDING PAYLOAD");
    console.log(payload);

    const options = {
      hostname,
      path: "/nibss/bvnr/VerifySingleBVN",
      method: "POST",
      headers: {
        "Sandbox-Key": sandboxKey,
        OrganisationCode: organisationCode,
        Authorization: authorizationHeader,
        SIGNATURE: signatureHeader,
        SIGNATURE_METH: signatureMethodHeader,
        Accept: "application/json",
        "Content-Type": "application/json",
      },
    };

    let data = "";

    const request = http.request(options, (response) => {
      response.on("error", error => {
        throw error;
      });

      response.on('data', (chunk) => {
        data += chunk;
      });

      response.on("end", () => {
        console.log("\nDECRYPTED RESPONSE");
        console.log(JSON.parse(cr.decrypt(data)));
      });
    });

    console.log("\nSENDING ENCYRPTED REQUEST");
    console.log(encrypted);

    request.write(encrypted);
    request.end();
  } catch (error) {
    throw error;
  }
}

BVN();
