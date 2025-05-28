<?php
/* Prerequisites

    Required key formats:
        Private key: 64-character hex (without 0x prefix)
        Public key: 130-character hex (04 + X + Y coordinates)

    Required PHP extensions:

	sudo apt-get install php-openssl

	Libraries via Composer:

	composer require kornrunner/keccak

    Limitations

	    Works only with AES-256-CTR (eth-crypto >= 2.0)
	    Requires precise serialization formats
	    Keys must use the same curve (secp256k1)
*/

use kornrunner\Keccak;
use BitWasp\Bitcoin\Crypto\EcAdapter\EcAdapter;
use BitWasp\Bitcoin\Key\Factory\PrivateKeyFactory;

function msgDecrypt(string $encryptedHex, string $privateKeyHex): string {
    // Split encrypted data into components
    $encrypted = hex2bin($encryptedHex);
    $iv = substr($encrypted, 0, 16);               // Initialization Vector (16 bytes)
    $ciphertext = substr($encrypted, 16, -32);     // Encrypted payload
    $mac = substr($encrypted, -32);                // Message Authentication Code (32 bytes)
    
    // Extract ephemeral public key (65 bytes)
    $ephemeralPublicKey = hex2bin(substr($encrypted, 16, 65));
    
    // Derive shared secret using ECDH
    $sharedSecret = Keccak::hash(hex2bin($privateKeyHex) ^ $ephemeralPublicKey, 256);
    
    // Generate encryption keys using HKDF
    $keys = hash_hkdf('sha512', $sharedSecret, 32, 'aes256ctr', $iv);
    
    // Validate message authenticity
    $calculatedMac = hash_hmac('sha256', $ciphertext, $keys, true);
    if (!hash_equals($mac, $calculatedMac)) {
        throw new Exception("Invalid MAC");
    }
    
    // Decrypt the payload
    $decrypted = openssl_decrypt(
        $ciphertext,
        'aes-256-ctr',
        $keys,
        OPENSSL_RAW_DATA,
        $iv
    );
    
    return $decrypted;
}
?>