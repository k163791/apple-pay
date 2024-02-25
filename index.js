const express = require("express");
const sshpk = require("sshpk");
const cryptoNative = require("crypto");
const forge = require("node-forge");
const ECKey = require("ec-key");
const asn1js = require("asn1js");
const pkijs = require("pkijs");
const fs = require("fs");

const TOKEN_EXPIRE_WINDOW = 122321231231233300000; // should be set to 5 minutes (300000 ms) per apple
const LEAF_CERTIFICATE_OID = "1.2.840.113635.100.6.29";
const INTERMEDIATE_CA_OID = "1.2.840.113635.100.6.2.14";
const SIGNINGTIME_OID = "1.2.840.113549.1.9.5";
const MERCHANT_ID_FIELD_OID = "1.2.840.113635.100.6.32";


const AppleRootCABuffer = fs.readFileSync("./AppleRootCA-G3.cer"); // TODO: cret path update
const AppleRootCAASN1 = asn1js.fromBER(
  new Uint8Array(AppleRootCABuffer).buffer
);
const AppleRootCA = new pkijs.Certificate({ schema: AppleRootCAASN1.result });

// const crypto = new Crypto.Crypto()
pkijs.setEngine(
  "newEngine",
  cryptoNative,
  new pkijs.CryptoEngine({
    name: "",
    crypto: cryptoNative,
    subtle: cryptoNative.subtle,
  })
);

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const checkCertificates = (certificates) => {
  if (certificates.length !== 2) {
    throw new Error(
      `Signature certificates number error: expected 2 but got ${certificates.length}`
    );
  }
  if (
    !certificates[0].extensions.find((x) => x.extnID === LEAF_CERTIFICATE_OID)
  ) {
    throw new Error(
      `Leaf certificate doesn't have extension: ${LEAF_CERTIFICATE_OID}`
    );
  }
  if (
    !certificates[1].extensions.find((x) => x.extnID === INTERMEDIATE_CA_OID)
  ) {
    throw new Error(
      `Intermediate certificate doesn't have extension: ${INTERMEDIATE_CA_OID}`
    );
  }
};

const checkSigningTime = (signerInfo) => {
  const signerInfoAttrs = signerInfo.signedAttrs.attributes;
  const attr = signerInfoAttrs.find((x) => x.type === SIGNINGTIME_OID);
  const signedTime = new Date(attr.values[0].toDate());
  const now = new Date();
  if (now - signedTime > TOKEN_EXPIRE_WINDOW) {
    throw new Error("Signature has expired");
  }
};

// validateSignature -
const validateSignature = (cmsSignedData, rootCA, signedData) => {
  return cmsSignedData.verify({
    //===================================
    // Should only contain 1 signer, verify with it
    //===================================
    signer: 0,
    trustedCerts: [rootCA],
    data: signedData,
    //===================================
    // Check x509 chain of trust
    //===================================
    checkChain: true,
    //===================================
    // Enable to show signature validation result
    //===================================
    extendedMode: true,
  });
};

const verifySignature = async (token) => {
  const cmsSignedBuffer = Buffer.from(token.signature, "base64");
  const cmsSignedASN1 = asn1js.fromBER(new Uint8Array(cmsSignedBuffer).buffer);
  const cmsContentSimpl = new pkijs.ContentInfo({
    schema: cmsSignedASN1.result,
  });
  const cmsSignedData = new pkijs.SignedData({
    schema: cmsContentSimpl.content,
  });
  checkCertificates(cmsSignedData.certificates);
  let headerKey = "";
  if (token.header && token.header.wrappedKey) {
    headerKey = token.header.wrappedKey;
  } else {
    headerKey = token.header.ephemeralPublicKey;
  }

  const p1 = Buffer.from(headerKey, "base64");
  const p2 = Buffer.from(token.data, "base64");
  const p3 = Buffer.from(token.header.transactionId, "hex");
  const signedData = Buffer.concat([p1, p2, p3]);
  const response = await validateSignature(
    cmsSignedData,
    AppleRootCA,
    signedData
  );
  if (!response.signatureVerified) {
    throw new Error("CMS signed data verification failed");
  }

  const signerInfo = cmsSignedData.signerInfos[0];
  checkSigningTime(signerInfo);
};

// generateSharedSecret -
const generateSharedSecret = (merchantPrivateKey, ephemeralPublicKey) => {
  //===================================
  // Use private key from payment processing certificate and the ephemeral public key to generate
  // the shared secret using Elliptic Curve Diffie*Hellman (ECDH)
  //===================================
  const ecPrivate = sshpk.parsePrivateKey(merchantPrivateKey, "ssh", {
    passphrase: "1234",
  });
  const ecPrivateKey = ecPrivate.toBuffer("pkcs8");

  const publicKey = new ECKey(ephemeralPublicKey, "spki");
  const privateKey = new ECKey(ecPrivateKey.toString("utf8"), "pem");

  return privateKey.computeSecret(publicKey).toString("hex");
};

// extractMerchantID -
const extractMerchantID = (merchantCert) => {
  //===================================
  // Extract merchant identification from public key certificate
  //===================================
  try {
    const info = forge.pki.certificateFromPem(merchantCert);
    const result = info["extensions"].filter(
      (d) => d.id === MERCHANT_ID_FIELD_OID
    );
    //-----------------------------------
    // Return
    //-----------------------------------
    return result[0].value.toString().substring(2);
  } catch (err) {
    throw new Error(`Unable to extract merchant ID from certificate: ${err}`);
  }
};

// getSymmetricKey -
const getSymmetricKey = (merchantId, sharedSecret) => {
  //===================================
  // Get KDF_Info as defined from Apple Pay documentation
  //===================================
  const KDF_ALGORITHM = "\x0did-aes256-GCM";
  const KDF_PARTY_V = Buffer.from(merchantId, "hex").toString("binary");
  const KDF_PARTY_U = "Apple";
  const KDF_INFO = KDF_ALGORITHM + KDF_PARTY_U + KDF_PARTY_V;
  //-----------------------------------
  // Create hash
  //-----------------------------------
  const hash = cryptoNative.createHash("sha256");
  hash.update(Buffer.from("000000", "hex"));
  hash.update(Buffer.from("01", "hex"));
  hash.update(Buffer.from(sharedSecret, "hex"));
  hash.update(KDF_INFO, "binary");
  //-----------------------------------
  // Return
  //-----------------------------------
  return hash.digest("hex");
  //-----------------------------------
};

const restoreRSASymmetricKey = (ephemeralPublicKey, paymentProcessorCert) => {
  let privateKey = sshpk.parsePrivateKey(paymentProcessorCert, "ssh", {
    passphrase: "1234",
  });
  privateKey = privateKey.toBuffer("pkcs8");

  const decrypted = cryptoNative.privateDecrypt(
    {
      key: privateKey,
      oaepHash: "sha256",
      padding: cryptoNative.constants.RSA_PKCS1_OAEP_PADDING,
    },
    Buffer.from(ephemeralPublicKey, "base64")
  );

  return decrypted.toString("hex");
};

const restoreSymmetricKey = (
  ephemeralPublicKey,
  merchantCert,
  paymentProcessorCert
) => {
  // return ephemeralPublicKey;
  const merchantId = extractMerchantID(merchantCert);
  const sharedSecret = generateSharedSecret(
    paymentProcessorCert,
    ephemeralPublicKey
  );

  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Return
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  return getSymmetricKey(merchantId, sharedSecret);
};

// decryptCiphertextFunc -
const decryptCiphertextFunc = (symmetricKey, encryptedData) => {
  //===================================
  // Get symmetric key and initialization vector
  //===================================
  const buf = Buffer.from(encryptedData, "base64");
  const SYMMETRIC_KEY = Buffer.from(symmetricKey, "hex");
  const IV = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // Initialization vector of 16 null bytes
  const CIPHERTEXT = buf.slice(0, -16);
  //-----------------------------------
  // Create and return a Decipher object that uses the given algorithm and password (key)
  //-----------------------------------
  const decipher = cryptoNative.createDecipheriv(
    "aes-256-gcm",
    SYMMETRIC_KEY,
    IV
  );
  const tag = buf.slice(-16, buf.length);
  decipher.setAuthTag(tag);
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Load encrypted token into Decipher object
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  let decrypted = decipher.update(CIPHERTEXT);
  decrypted += decipher.final();
  //:::::::::::::::::::::::::::::::::::
  // Return
  //:::::::::::::::::::::::::::::::::::
  return decrypted;
  //:::::::::::::::::::::::::::::::::::
};

const prepTabaPayToken = (encryptedToken, decryptedToken) => {
  let preppedToken = {};
  preppedToken["accountNumber"] =
    decryptedToken["applicationPrimaryAccountNumber"];
  preppedToken["expirationDate"] =
    "20" + decryptedToken["applicationExpirationDate"].substring(0, 4);
  preppedToken["cryptogram"] =
    decryptedToken["paymentData"]["onlinePaymentCryptogram"];
  preppedToken["transactionID"] = encryptedToken["transactionIdentifier"];
  //===================================
  // eciIndicator will not be present if card is not Visa
  //===================================
  preppedToken["eciIndicator"] = decryptedToken["paymentData"]["eciIndicator"];
  preppedToken["network"] = encryptedToken["paymentMethod"]["network"];
  preppedToken["type"] = encryptedToken["paymentMethod"]["type"];
  //===================================
  // Return
  //===================================
  return preppedToken;
  //===================================
};

app.post("/api/decryptToken", async (req, res) => {
  try {
    const token = req.body.encryptedToken;
    const key =
      token.paymentData.version === "RSA_v1"
        ? "wrappedKey"
        : "ephemeralPublicKey";
    const ephemeralPublicKey = token["paymentData"]["header"][key];
    const encryptedData = token["paymentData"]["data"];

    // 1234
    // TODO: cert path update
    const merchantCert = fs.readFileSync("./MerchantIdentity.pem", "utf8");
    const paymentProcessorCert = fs.readFileSync(
      "./PaymentProcessing.crt.pem",
      "utf8"
    );

    await verifySignature(token.paymentData);

    let symmetricKey = "";
    try {
      if (key === "ephemeralPublicKey") {
        symmetricKey = restoreSymmetricKey(
          ephemeralPublicKey,
          merchantCert,
          paymentProcessorCert
        );
      } else {
        symmetricKey = restoreRSASymmetricKey(ephemeralPublicKey, merchantCert);
      }
    } catch (err) {
      throw new Error(`Restore symmetric key failed: ${err.message}`);
    }

    try {
      //-----------------------------------
      // Use the symmetric key to decrypt the value of the data key
      //-----------------------------------
      const decrypted = JSON.parse(
        decryptCiphertextFunc(symmetricKey, encryptedData)
      );
      const preppedToken = prepTabaPayToken(token.paymentData, decrypted);
      //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      // Send decrypted token back to frontend
      //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      res.send(preppedToken);
    } catch (err) {
      throw new Error(`Decrypt cipher data failed: ${err.message}`);
    }
  } catch (err) {
    console.error("Error occurred");
    return res.status(400).json(err);
  }
});

app.listen(8001, () => {
  console.info("App is listening on PORT: 8001");
});
