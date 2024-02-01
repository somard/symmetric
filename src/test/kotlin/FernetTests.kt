import junit.framework.Assert.assertEquals
import org.junit.Before
import org.junit.Test

class FernetTests {

    private lateinit var objFernet: Fernet

    @Before
    fun setUp(){
        objFernet = Fernet()
    }

    @Test
    fun testEncryptionDecryption() {

        val key = Fernet().generateKey()
        val message = "Hello, Kotlin Fernet!"
        val encrypted = objFernet.encrypt(key, message)
        val decrypted = objFernet.decrypt(key, encrypted)

        assertEquals(message, decrypted)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testDecryptionWithInvalidKey() {
        val key = objFernet.generateKey()
        val differentKey = objFernet.generateKey()
        val message = "Hello, Kotlin Fernet!"
        val encrypted = objFernet.encrypt(key, message)

        objFernet.decrypt(differentKey, encrypted) // Should throw IllegalArgumentException
    }

    @Test(expected = IllegalArgumentException::class)
    fun testTamperedToken() {
        val key = objFernet.generateKey()
        val message = "Hello, Kotlin Fernet!"
        val encrypted = objFernet.encrypt(key, message)
        val tampered = encrypted.dropLast(1) + 'A'

        objFernet.decrypt(message, tampered)
    }
}