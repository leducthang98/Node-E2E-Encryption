const crypto = require('node:crypto');

// DH
// the basic one, very slow
async function basicDiffieHellman() {
    // create diffie hellman groups, Alice and Bob use the common key as modp15 group
    const alice = crypto.getDiffieHellman('modp15')
    const bob = crypto.getDiffieHellman('modp15')

    // generate keypair
    alice.generateKeys()
    bob.generateKeys()

    // generate shared key from alice
    const aliceShared = alice.computeSecret(bob.getPublicKey(), null, 'hex')
    const bobShared = bob.computeSecret(alice.getPublicKey(), null, 'hex')

    return {
        aliceShared,
        bobShared
    }
}

// ECDH
// more secure, much faster than DH
async function ellipticCurveDiffieHellman() {

    // fastest curved
    const alice = crypto.createECDH('secp256k1');
    alice.generateKeys();

    // secp256k1 is considered as the common key
    const bob = crypto.createECDH('secp256k1');
    bob.generateKeys();

    const alicePublicKeyBase64 = alice.getPublicKey().toString('base64');
    const bobPublicKeyBase64 = bob.getPublicKey().toString('base64');

    // exchange shared key
    const aliceShared = alice.computeSecret(bobPublicKeyBase64, 'base64', 'hex');
    const bobShared = bob.computeSecret(alicePublicKeyBase64, 'base64', 'hex');

    return {
        aliceShared,
        bobShared
    }
}

async function useAESWithECDH() {
    
    const {
        aliceShared,
        bobShared
    } = await ellipticCurveDiffieHellman()

    // This is an example using shared key to transfer message from Alice to Bob using ECDH + AES

    // --- ALICE SEND MESSAGE
    const msgFromAlice = "This is Alice"
    const IV = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(aliceShared, 'hex'), IV)
    const msgFromAliceEncrypted = cipher.update(msgFromAlice, 'utf8', 'hex') + cipher.final('hex')
    const authTag = cipher.getAuthTag().toString('hex')
    const payloadMessageToBeSent = Buffer.from(`${IV.toString('hex')}${msgFromAliceEncrypted}${authTag}`, 'hex').toString('base64') // send msg base64 to bob


    // --- BOB DECODE MESSAGE
    try {
        const payloadRecv = Buffer.from(payloadMessageToBeSent, 'base64').toString('hex')
        const payloadIV = payloadRecv.substring(0, 32)
        const payloadEncrypted = payloadRecv.substring(32, payloadRecv.length - 32)
        const payloadAuthTag = payloadRecv.substring(payloadRecv.length - 32)
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            Buffer.from(bobShared, 'hex'),
            Buffer.from(payloadIV, 'hex'))
            .setAuthTag(Buffer.from(payloadAuthTag, 'hex'))

        let messageDecrypted = decipher.update(payloadEncrypted, 'hex', 'utf8') + decipher.final('utf8')
        console.info(messageDecrypted)
    } catch (error) {
        console.error('err:', error)
    }
}

useAESWithECDH()

