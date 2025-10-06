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
            entries.filterTo(EnumSet.noneOf(CharacterClass::class.java)) {
                it.range != null && serialized.testBit(it.bit)
            }
    }
}
