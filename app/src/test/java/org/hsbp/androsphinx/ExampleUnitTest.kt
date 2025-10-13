package org.hsbp.androsphinx

import org.junit.Test

import org.junit.Assert.*
import java.math.BigInteger

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */

val RWD_INPUT = BigInteger("AA".repeat(32), 16)

@Suppress("SpellCheckingInspection")
const val DERIVED_ULSD_0 = "2UH@/%XoTb+T-RT*tipUqT+b\'lYQ*kUiPOdq@sK"

@Suppress("SpellCheckingInspection")
const val DERIVED_ULSD_8 = "iPOdq@sK"

@Suppress("SpellCheckingInspection")
const val DERIVED_ULSD_20_SYMBOLS = ".:;#$%&" // not sorted on purpose

const val TEST_XOR_MASK = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"

class ExampleUnitTest {
    @Test
    fun encodingTest() {
        val pwdUpperLowerSymbolsDigits0 = Rule(setOf(CharacterClass.UPPER, CharacterClass.LOWER, CharacterClass.DIGITS),
            SYMBOL_SET.toSet(), BigInteger.ZERO, BigInteger.ZERO, null).derive(RWD_INPUT)
        assertEquals(DERIVED_ULSD_0, pwdUpperLowerSymbolsDigits0)

        val pwdUpperLowerSymbolsDigits8 = Rule(setOf(CharacterClass.UPPER, CharacterClass.LOWER, CharacterClass.DIGITS),
            SYMBOL_SET.toSet(), 8.toBigInteger(), BigInteger.ZERO, null).derive(RWD_INPUT)
        assertEquals(DERIVED_ULSD_8, pwdUpperLowerSymbolsDigits8)
    }

    @Test
    fun characterClassSerializationTest() {
        for (expected in 0 .. 7) {
            val set = CharacterClass.parse(expected.toBigInteger())
            val serialized = CharacterClass.serialize(set)
            assertEquals(expected.toBigInteger(), serialized)
        }
    }

    @Test
    fun ruleSerializationTest() {
        val upperLower20 = Rule(setOf(CharacterClass.UPPER, CharacterClass.LOWER),
            emptySet(), 20.toBigInteger(), BigInteger.ZERO, BigInteger.ZERO)
        val upperLower20bytes = upperLower20.serialize()
        assertEquals(RULE_BYTES_LENGTH, upperLower20bytes.size)
        assertEquals(Rule.parse(upperLower20bytes), upperLower20)
        val upperLowerSelectSymbols20xor = Rule(setOf(CharacterClass.UPPER, CharacterClass.LOWER),
            DERIVED_ULSD_20_SYMBOLS.toSet(), 20.toBigInteger(), BigInteger(TEST_XOR_MASK, 16), 23.toBigInteger())
        val upperLowerSelectSymbols20xorBytes = upperLowerSelectSymbols20xor.serialize()
        assertEquals(RULE_BYTES_LENGTH, upperLowerSelectSymbols20xorBytes.size)
        assertEquals(Rule.parse(upperLowerSelectSymbols20xorBytes), upperLowerSelectSymbols20xor)
        val upperLowerSelectSymbols20xorS = Rule(setOf(CharacterClass.UPPER, CharacterClass.LOWER, CharacterClass.SYMBOLS),
            DERIVED_ULSD_20_SYMBOLS.toSet(), 20.toBigInteger(), BigInteger(TEST_XOR_MASK, 16), 23.toBigInteger())
        assertEquals(Rule.parse(upperLowerSelectSymbols20xorS.serialize()), upperLowerSelectSymbols20xor)
    }
}
