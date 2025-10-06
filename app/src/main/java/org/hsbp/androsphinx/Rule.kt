package org.hsbp.androsphinx

import org.hsbp.androsphinx.DerivationContext
import org.hsbp.androsphinx.Protocol.Companion.calculateCheckDigit
import java.math.BigInteger

const val SYMBOL_SET = " !\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~"
const val POSITIVE: Int = 1
const val RULE_SHIFT: Int = 7
const val XOR_MASK_BYTES: Int = 64

private val SIZE_MASK = BigInteger.valueOf(0x7F)
val CHECK_DIGIT_MASK: BigInteger = BigInteger.valueOf(0x1F)
private val SYMBOL_OFFSET = CharacterClass.entries.count { it.range != null } + RULE_SHIFT
private val CHECK_DIGIT_SHIFT = SYMBOL_OFFSET + SYMBOL_SET.length

data class Rule(val charClasses: Set<CharacterClass>, val symbols: Set<Char>,
                val size: BigInteger, val xorMask: BigInteger, val checkDigit: BigInteger? = null) {
    fun serialize(): ByteArray {
        val symbolIndices = SYMBOL_SET.mapIndexedNotNull { i, ch -> if (ch in symbols) (i + SYMBOL_OFFSET) else null }
        val r = CharacterClass.serialize(charClasses).shiftLeft(RULE_SHIFT).or(size.and(SIZE_MASK))
        val withSymbols = symbolIndices.fold(r) { acc, pos -> acc.setBit(pos) }
        val withCheckDigit = withSymbols.or(checkDigit!!.and(CHECK_DIGIT_MASK).shiftLeft(CHECK_DIGIT_SHIFT))
        val blob = withCheckDigit.shiftLeft(XOR_MASK_BYTES * 8).or(xorMask).toByteArray()
        return when {
            blob.size < RULE_BYTES_LENGTH -> ByteArray(RULE_BYTES_LENGTH - blob.size) + blob
            blob.size > RULE_BYTES_LENGTH -> blob.sliceArray(blob.size - RULE_BYTES_LENGTH until blob.size)
            else -> blob
        }
    }

    fun withCheckDigit(newCheckDigit: BigInteger): Rule =
        Rule(charClasses, symbols, size, xorMask, newCheckDigit)

    fun withXorMaskFor(rwd: ByteArray): Rule =
        Rule(charClasses, symbols, size, findXorMask(rwd), calculateCheckDigit(rwd))

    private fun findXorMask(rwd: ByteArray): BigInteger {
        val rs = size.toInt()
        if (1 <= rs && rs < 8) return generateRandomXorMask()
        val hashedRwd = BigInteger(POSITIVE, DerivationContext.PASSWORD.foldHash(rwd))
        while (true) {
            val xorMask = generateRandomXorMask()
            val candidate = derive(hashedRwd.xor(xorMask)).asIterable()
            if (charClasses.all { cc ->
                    (cc.range ?: symbols).intersect(candidate).isNotEmpty()
                }) return xorMask
        }
    }

    fun derive(source: ByteArray): String = derive(BigInteger(POSITIVE,
        DerivationContext.PASSWORD.foldHash(source)).xor(xorMask))

    private fun derive(rwd: BigInteger): String {
        require(charClasses.isNotEmpty() || symbols.isNotEmpty()) { "At least one character class or symbol must be allowed." }
        val order = arrayOf(CharacterClass.UPPER, CharacterClass.LOWER, CharacterClass.DIGITS)
        val chars = order.filter(charClasses::contains).flatMap { it.range!!.sorted() }.toList() + symbols.sorted()
        val length = size.toInt()
        val password = encode(rwd, chars, length)
        val result = if (length > 0) subArrayWithCleaning(password, length) else password
        val str = String(result)
        result.fill('\u0000')
        return str
    }

    companion object {
        fun parse(serialized: ByteArray): Rule {
            val xorMaskOffset = serialized.size - XOR_MASK_BYTES
            val xorMask = BigInteger(POSITIVE, serialized.sliceArray(xorMaskOffset until serialized.size))
            val v = BigInteger(POSITIVE, serialized.sliceArray(0 until xorMaskOffset))
            val size = v.and(SIZE_MASK)
            val charClasses = CharacterClass.parse(v.shiftRight(RULE_SHIFT))
            val symbols = SYMBOL_SET.asIterable().filterIndexedTo(mutableSetOf()) {
                    i, _ -> v.testBit(i + SYMBOL_OFFSET)
            }
            val checkDigit = v.shiftRight(CHECK_DIGIT_SHIFT).and(CHECK_DIGIT_MASK)
            return Rule(charClasses, symbols, size, xorMask, checkDigit)
        }
    }
}

private fun encode(raw: BigInteger, chars: List<Char>, size: Int): CharArray {
    val result = mutableListOf<Char>()
    var v = raw
    val divisor = chars.size.toBigInteger()
    while ((size > 0 && result.size < size) || (size == 0 && v != BigInteger.ZERO)) {
        val divMod = v.divideAndRemainder(divisor)
        v = divMod[0]
        result.add(chars[divMod[1].toInt()])
    }
    val password = result.toCharArray()
    password.reverse()
    result.forEachIndexed { index, _ -> result[index] = '\u0000' }
    return password
}

private fun subArrayWithCleaning(input: CharArray, size: Int): CharArray {
    if (input.size == size) return input
    val result = input.sliceArray(0 until size)
    input.fill('\u0000')
    return result
}