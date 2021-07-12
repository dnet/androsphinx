package org.hsbp.equihash

class Equihash {
    companion object {
        @JvmStatic external fun solve(n: Int, k: Int, seed: ByteArray): ByteArray?
        @JvmStatic external fun verify(n: Int, k: Int, seed: ByteArray, sol: ByteArray): Boolean
    }
}