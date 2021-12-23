package org.hsbp.androsphinx

import java.math.BigInteger

const val SYMBOL_SET = " !\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~"
const val POSITIVE: Int = 1
const val RULE_SHIFT: Int = 7
const val XOR_MASK_BYTES: Int = 32

private val SIZE_MASK = BigInteger.valueOf(0x7F)
private val CHECK_DIGIT_MASK = BigInteger.valueOf(0x1F)
private val SYMBOL_OFFSET = CharacterClass.values().count { it.range != null } + RULE_SHIFT
private val CHECK_DIGIT_SHIFT = SYMBOL_OFFSET + SYMBOL_SET.length

data class Rule(val charClasses: Set<CharacterClass>, val symbols: Set<Char>,
                val size: BigInteger, val xorMask: BigInteger, val checkDigit: BigInteger? = null) {
    fun serialize(): ByteArray {
        val symbolIndices = SYMBOL_SET.mapIndexedNotNull { i, ch -> if (ch in symbols) (i + SYMBOL_OFFSET) else null }
        val r = CharacterClass.serialize(charClasses).shiftLeft(RULE_SHIFT).or(size.and(SIZE_MASK))
        val withSymbols = symbolIndices.fold(r) { acc, pos -> acc.setBit(pos) }
        val withCheckDigit = withSymbols.or(checkDigit!!.and(CHECK_DIGIT_MASK).shiftLeft(CHECK_DIGIT_SHIFT))
        val blob = withCheckDigit.shiftLeft(XOR_MASK_BYTES * 8).or(xorMask).toByteArray()
        return if (blob.size < RULE_BYTES_LENGTH) ByteArray(RULE_BYTES_LENGTH - blob.size) { 0 } + blob else blob
    }

    fun withCheckDigit(newCheckDigit: BigInteger): Rule =
        Rule(charClasses, symbols, size, xorMask, newCheckDigit)

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
