
interface ISymmetricable {
    fun encrypt(key: String, message: String): String
    fun decrypt(key: String, token: String): String
}