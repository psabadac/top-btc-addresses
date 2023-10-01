import com.github.shiguruikai.combinatoricskt.combinationsWithRepetition
import org.bitcoinj.core.*
import org.bitcoinj.core.Utils
import org.bitcoinj.script.Script
import org.bitcoinj.script.ScriptBuilder
import java.io.File
import java.math.BigInteger
import java.security.MessageDigest

data class BtcAddress(
    val name: String,
    val hex: String,
    val dec: String,
    val wifc: String,
    val wifu: String,
    val p2pkhc: String,
    val p2shc: String,
    val bech32c: String,
    val p2pkhu: String,
) {

    fun keys() = listOf(
        hex,
        dec,
        wifc,
        wifu
    )

    fun addresses() = listOf(
        p2pkhc,
        p2shc,
        bech32c,
        p2pkhu
    )

    override fun toString(): String = "BtcAddress(\n" +
            "\tname = '$name'\n" +
            "\tHEX = $hex\n" +
            "\tDEC = $dec\n" +
            "\tWIF(c) = $wifc\n" +
            "\tWIF(u) = $wifu\n" +
            "\tP2PKH(c) = $p2pkhc\n" +
            "\tP2SH(c) = $p2shc\n" +
            "\tBECH32(c) = $bech32c\n" +
            "\tP2PKH(u) = $p2pkhu\n)\n"
}

object Utils {
    private val MAX = BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", 16)
    private val sha256 = MessageDigest.getInstance("SHA-256")
    private val networkParameters = NetworkParameters.fromID(NetworkParameters.ID_MAINNET)
    private val addresses = File(object {}.javaClass.getResource("top_btc_addresses.txt").file).useLines { it.toList() }

    fun getAddressesForPassphrase(passphrase: String) {
        brainwallet("Brainwallet", passphrase)
        brainwallet("Brainwallet (uppercase)", passphrase.uppercase())
        brainwallet("Brainwallet (reversed)", passphrase.reversed())
        brainwallet("Brainwallet 2x", passphrase, 2)

        val spacedChars = passphrase.toCharArray()
        for (c in " `~!@#$%^&*()_+=-{}|:\"<>?/.,';\\][") {
            val newPassphrase = spacedChars.joinToString("$c")
            brainwallet("Brainwallet spaced $c", newPassphrase)
        }


        for (c in "0123456789abcdef") {
            paddedWallet("Binary (left padded with '$c')", passphrase, true, c)
            paddedWallet("Binary (right padded with '$c')", passphrase, false, c)
        }
    }

    fun getAddressFromPhoneNumbers() {
        val elements = (0..9).toList()
        val separators = " .-"
        for (first in elements.combinationsWithRepetition(3)) {
            for (last in elements.combinationsWithRepetition(4)) {
                val passphrase = first.joinToString("") + last.joinToString("")
                brainwallet("Brainwallet", passphrase)
                print("$passphrase\r")

                for (s in separators) {
                    val passphrase = first.joinToString("") + s + last.joinToString("")
                    brainwallet("Brainwallet", passphrase)
                    print("$passphrase\r")
                }
            }
        }
    }

    private fun checkAddress(btcAddress: BtcAddress?) = btcAddress?.addresses()?.any { it in addresses } ?: false

    private fun paddedWallet(name: String, passphrase: String, left: Boolean = true, padChar: Char = '0'): BtcAddress? {
        val startKey = BigInteger(passphrase.toByteArray()).toString(16)
        val privateKeyPadded = if (left) startKey.padStart(64, padChar) else startKey.padEnd(64, padChar)
        val privateKey = BigInteger(privateKeyPadded, 16)
        return if (privateKey < BigInteger.ZERO || privateKey > MAX) null else btcWallet(name, privateKey)
    }

    private fun brainwallet(name: String, passphrase: String, privateKeyIterations: Int = 1): BtcAddress? {
        val privateKey = passphraseToPrivateKey(passphrase, privateKeyIterations) ?: return null
        return btcWallet(name, privateKey)
    }

    private fun btcWallet(name: String, privateKey: BigInteger): BtcAddress {
        val hex = privateKey.toString(16).padStart(64, '0')
        val dec = privateKey.toString()
        val wifc = ECKey.fromPrivate(privateKey, true).getPrivateKeyAsWiF(networkParameters)
        val wifu = ECKey.fromPrivate(privateKey, false).getPrivateKeyAsWiF(networkParameters)

        val p2pkhc = p2pkh(privateKey, true)
        val p2shc = p2shc(privateKey)
        val bech32c = bech32c(privateKey)
        val p2pkhu = p2pkh(privateKey, false)

        val btcAddress = BtcAddress(
            name = name,
            hex = hex,
            dec = dec,
            wifc = wifc,
            wifu = wifu,
            p2pkhc = p2pkhc,
            p2shc = p2shc,
            bech32c = bech32c,
            p2pkhu = p2pkhu
        )

        if (checkAddress(btcAddress)) {
            println(btcAddress.hex)
        }

        return btcAddress
    }

    private fun passphraseToPrivateKey(passphrase: String, privateKeyIterations: Int = 1): BigInteger? {
        var privateKey: BigInteger? = null
        try {
            var digest = sha256.digest(passphrase.toByteArray())
            repeat(privateKeyIterations - 1) {
                digest = sha256.digest(digest)
            }
            privateKey = BigInteger(digest)
        } catch (e: ArrayIndexOutOfBoundsException) {
            return null
        }
        return if (privateKey < BigInteger.ZERO || privateKey > MAX) null else privateKey
    }

    private fun p2pkh(privateKey: BigInteger, compressed: Boolean) =
        Address.fromKey(
            networkParameters,
            ECKey.fromPrivate(privateKey, compressed),
            Script.ScriptType.P2PKH
        ).toString()

    private fun p2shc(privateKey: BigInteger) =
        LegacyAddress.fromScriptHash(
            networkParameters, Utils.sha256hash160(
                ScriptBuilder
                    .createP2WPKHOutputScript(ECKey.fromPrivate(privateKey).pubKeyHash)
                    .program
            )
        ).toString()

    private fun bech32c(privateKey: BigInteger) =
        Address.fromKey(
            networkParameters,
            ECKey.fromPrivate(privateKey, true),
            Script.ScriptType.P2WPKH
        ).toString()
}