package org.hsbp.androsphinx

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.*
import kotlin.experimental.and
import kotlin.experimental.or
import kotlin.math.log

enum class CharacterClass(private val bit: Byte, internal val range: Set<Char>) {
    UPPER(bit = 1, range = CharRange('A', 'Z').toSet()),
    LOWER(bit = 2, range = CharRange('a', 'z').toSet()),
    SYMBOLS(bit = 4, range = CharRange(' ', '/') union CharRange(':', '@') union
            CharRange('[', '`') union CharRange('{', '~')),
    DIGITS(bit = 8, range = CharRange('0', '9').toSet());

    companion object {
        fun serialize(values: Set<CharacterClass>): Byte {
            return values.fold(0.toByte()) { acc, cc -> acc or cc.bit }
        }

        fun parse(serialized: Byte): Set<CharacterClass> =
            values().filterTo(EnumSet.noneOf(CharacterClass::class.java)) {
                it.bit and serialized == it.bit }

        fun derive(rwd: ByteArray, rule: Set<CharacterClass>, size: Int): CharArray {
            require(rule.isNotEmpty()) { "At least one character class must be allowed." }
            val order = arrayOf(SYMBOLS, UPPER, LOWER, DIGITS)
            val chars = order.filter(rule::contains).flatMap { it.range.sorted() }.toList()
            val password = encode(rwd, chars)
            return if (size > 0) subArrayWithCleaning(password, size) else password
        }

        private fun encode(raw: ByteArray, chars: List<Char>): CharArray {
            val l = raw.size
            val r = l.rem(4)
            val input = if (r == 0) raw else raw + ByteArray(r) { 0 }
            val ib = ByteBuffer.wrap(input).order(ByteOrder.BIG_ENDIAN).asIntBuffer()
            val charSize = chars.size.toLong()
            val outFact = log(0x100000000.toDouble(), charSize.toDouble()).toInt() + 1
            val out = CharArray(outFact * ib.capacity())
            var index = 0
            while (ib.hasRemaining()) {
                var word = ib.get().toLong() and 0xFFFFFFFF
                repeat(outFact) {
                    out[index++] = chars[word.rem(charSize).toInt()]
                    word /= charSize
                }
            }
            val olen = (if (r == 0) 0 else r + 1) + l / 4 * outFact
            return subArrayWithCleaning(out, olen)
        }

        private fun subArrayWithCleaning(input: CharArray, size: Int): CharArray {
            if (input.size == size) return input
            val result = input.sliceArray(0 until size)
            input.fill('\u0000')
            return result
        }
    }
}