import org.junit.jupiter.api.Test

class UtilsTest {
    @Test
    fun password_found_prints_private_key() {
        Utils.getAddressesForPassphrase("password")
    }
}