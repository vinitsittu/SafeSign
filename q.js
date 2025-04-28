let publicKeyObj, privateKeyObj;
let signPublicKeyObj, signPrivateKeyObj;

async function generateKeys() {
    const keyPair = await window.crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true,
        ["encrypt", "decrypt"]
    );
    publicKeyObj = keyPair.publicKey;
    privateKeyObj = keyPair.privateKey;

    const publicKey = await window.crypto.subtle.exportKey("spki", publicKeyObj);
    const privateKey = await window.crypto.subtle.exportKey("pkcs8", privateKeyObj);

    document.getElementById('publicKey').value = convertToPem(publicKey, "PUBLIC KEY");
    document.getElementById('privateKey').value = convertToPem(privateKey, "PRIVATE KEY");
}

async function generateSignKeys() {
    const keyPair = await window.crypto.subtle.generateKey(
        { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true,
        ["sign", "verify"]
    );
    signPublicKeyObj = keyPair.publicKey;
    signPrivateKeyObj = keyPair.privateKey;

    document.getElementById('signPublicKey').value = JSON.stringify(await crypto.subtle.exportKey('jwk', signPublicKeyObj), null, 2);
    document.getElementById('signPrivateKey').value = JSON.stringify(await crypto.subtle.exportKey('jwk', signPrivateKeyObj), null, 2);
}

async function encryptMessage() {
    const message = document.getElementById('encryptMessage').value;
    if (!publicKeyObj) { alert("Generate keys first!"); return; }

    const encoded = new TextEncoder().encode(message);
    const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKeyObj, encoded);
    document.getElementById('encryptedText').value = bufferToBase64(encrypted);
}

async function decryptMessage() {
    const encryptedBase64 = document.getElementById('encryptedText').value;
    if (!privateKeyObj) { alert("Generate keys first!"); return; }

    const encryptedBytes = base64ToBuffer(encryptedBase64);

    try {
        const decrypted = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKeyObj, encryptedBytes);
        document.getElementById('decryptedText').value = new TextDecoder().decode(decrypted);
    } catch (e) {
        document.getElementById('decryptedText').value = "Decryption Failed!";
    }
}

async function signMessage() {
    const message = document.getElementById('messageToSign').value;
    if (!signPrivateKeyObj) { alert("Generate signing keys first!"); return; }

    const encoded = new TextEncoder().encode(message);
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signPrivateKeyObj, encoded);

    document.getElementById('signature').value = bufferToBase64(signature);
}

async function verifySignature() {
    const message = document.getElementById('messageToVerify').value;
    const signatureBase64 = document.getElementById('signatureToVerify').value;
    const signPublicKeyJwk = document.getElementById('signPublicKey').value;

    if (!signPublicKeyJwk) { alert("Paste or generate signing public key first!"); return; }

    const encoded = new TextEncoder().encode(message);
    const signature = base64ToBuffer(signatureBase64);

    try {
        const importedPublicKey = await crypto.subtle.importKey(
            'jwk',
            JSON.parse(signPublicKeyJwk),
            { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
            true,
            ['verify']
        );

        const isValid = await crypto.subtle.verify(
            "RSASSA-PKCS1-v1_5",
            importedPublicKey,
            signature,
            encoded
        );

        document.getElementById('verificationResult').value = isValid ? "✅ Signature is VALID" : "❌ Signature is INVALID";
    } catch (error) {
        console.error(error);
        document.getElementById('verificationResult').value = "❌ Verification Failed!";
    }
}

// Utility
function convertToPem(buffer, label) {
    const base64Key = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    const pemKey = base64Key.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${label}-----\n${pemKey}\n-----END ${label}-----`;
}

function bufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}
