// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import java.math.BigInteger
import java.util.*

enum class CharacterClass(private val bit: Int, internal val range: Set<Char>?, val description: Int) {
    UPPER(bit = 0, range = CharRange('A', 'Z').toSet(), description = R.string.character_class_upper),
    LOWER(bit = 1, range = CharRange('a', 'z').toSet(), description = R.string.character_class_lower),
    SYMBOLS(bit = -1, range = null, description = R.string.character_class_symbols), // UI only, never encoded
    DIGITS(bit = 2, range = CharRange('0', '9').toSet(), description = R.string.character_class_digits);

    companion object {
        fun serialize(values: Set<CharacterClass>): BigInteger {
            return values.filter { it.range != null }.fold(BigInteger.ZERO) { acc, cc -> acc.setBit(cc.bit) }
        }

        fun parse(serialized: BigInteger): Set<CharacterClass> =
            values().filterTo(EnumSet.noneOf(CharacterClass::class.java)) {
                it.range != null && serialized.testBit(it.bit)
            }

        fun derive(rwd: BigInteger, rule: Set<CharacterClass>, size: Int, syms: Set<Char> = SYMBOL_SET.toSet()): CharArray {
            require(rule.isNotEmpty() || syms.isNotEmpty()) { "At least one character class or symbol must be allowed." }
            val order = arrayOf(UPPER, LOWER, DIGITS)
            val chars = order.filter(rule::contains).flatMap { it.range!!.sorted() }.toList() + syms.sorted()
            val password = encode(rwd, chars, size)
            return if (size > 0) subArrayWithCleaning(password, size) else password
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
    }
}
