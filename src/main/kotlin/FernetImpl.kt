
//https://cryptography.io/en/latest/fernet/

import java.security.SecureRandom
    import javax.crypto.Cipher
    import javax.crypto.Mac
    import javax.crypto.spec.IvParameterSpec
    import javax.crypto.spec.SecretKeySpec
    import java.util.*

    class Fernet: ISymmetricable {
        companion object {
            private const val AES_KEY_SIZE = 16 // measured in bytes == 128 bits for AES key
            private const val HMAC_KEY_SIZE = 16 // 128 bits for HMAC key
            private const val IV_SIZE = 16 // 128 bits for IV
            private const val TOKEN_VERSION: Byte = 0x80.toByte()  //token combines cyphertext, hmac, aeskey iv etc
            private const val AES = "AES"
            const val SHA128 = "HmacSHA128"
            private const val SHA256 = "HmacSHA256"
            const val SHA512 = "HmacSHA512"
            private const val CBC_PADDING = "AES/CBC/PKCS5Padding"
        }

        fun generateKey(): String {
            val random = SecureRandom()
            val key = ByteArray(AES_KEY_SIZE + HMAC_KEY_SIZE) // Generate a 256-bit key
            random.nextBytes(key)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(key)
        }

        override fun encrypt(keyBase64: String, message: String): String {
            val key = Base64.getUrlDecoder().decode(keyBase64)
            val aesKey = key.copyOfRange(0, AES_KEY_SIZE)
            val hmacKey = key.copyOfRange(AES_KEY_SIZE, key.size)

            val iv = ByteArray(IV_SIZE).apply { SecureRandom().nextBytes(this) }
            val cipher = Cipher.getInstance(CBC_PADDING).apply {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, AES), IvParameterSpec(iv))
            }
            val ciphertext = cipher.doFinal(message.toByteArray(Charsets.UTF_8))

            val payload = byteArrayOf(TOKEN_VERSION) + iv + ciphertext
            val hmac = Mac.getInstance(SHA256).apply {
                init(SecretKeySpec(hmacKey, SHA256))
            }
            val signature = hmac.doFinal(payload)

            return Base64.getUrlEncoder().withoutPadding().encodeToString(payload + signature)
        }

        override fun decrypt(keyBase64: String, tokenBase64: String): String {
            val key = Base64.getUrlDecoder().decode(keyBase64)
            val aesKey = key.copyOfRange(0, AES_KEY_SIZE)
            val HMACKey = key.copyOfRange(AES_KEY_SIZE, key.size)
            val token = Base64.getUrlDecoder().decode(tokenBase64)

            val payload = token.copyOfRange(0, token.size - 32)
            val signature = token.copyOfRange(token.size - 32, token.size)

            Mac.getInstance(SHA256).apply {
                init(SecretKeySpec(HMACKey, SHA256))
            }
            if (!Mac.getInstance(SHA256).apply { init(SecretKeySpec(HMACKey, SHA256)) }
                    .doFinal(payload).contentEquals(signature)) {
                throw IllegalArgumentException("Invalid HMAC signature")
            }

            val iv = payload.copyOfRange(1, IV_SIZE + 1)
            val ciphertext = payload.copyOfRange(IV_SIZE + 1, payload.size)

            val cipher = Cipher.getInstance(CBC_PADDING).apply {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, AES), IvParameterSpec(iv))
            }

            return String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        }
    }