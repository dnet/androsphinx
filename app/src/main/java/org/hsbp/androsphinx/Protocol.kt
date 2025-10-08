// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import com.danrusu.pods4k.immutableArrays.ImmutableByteArray
import com.danrusu.pods4k.immutableArrays.toMutableArray
import org.hsbp.equihash.Equihash
import java.io.Closeable
import java.io.InputStream
import java.lang.RuntimeException
import java.math.BigInteger
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.net.ssl.SSLSocketFactory
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract
import com.github.michaelbull.itertools.permutations
import kotlin.collections.component1
import kotlin.collections.component2

const val RULE_BYTES_LENGTH: Int = 70
const val AUTH_NONCE_BYTES: Int = 32
const val VERSION_LENGTH: Int = 1
const val ENCRYPTED_RULE_LENGTH: Int = CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES + RULE_BYTES_LENGTH + VERSION_LENGTH

const val OPRF_BYTES: Int = 64

private val RESPONSE_OK = "ok".toByteArray()
private val RESPONSE_AUTH = byteArrayOf(0, 4) + "auth".toByteArray()
private val BLOB_FAIL = "fail".toByteArray()
private val RESPONSE_FAIL = byteArrayOf(0, 4) + BLOB_FAIL
const val TS_EPSILON: Long = 1200 // TODO make configurable

class Protocol {
    enum class Command(val code: Byte,
                       val requiredResponses: RequiredResponses = RequiredResponses.ALL) {
        CREATE(0x00),
        CREATE_DKG(0xf0.toByte()),
        READ(0x33, requiredResponses = RequiredResponses.THRESHOLD),
        UNDO(0x55),
        CHALLENGE_CREATE(0x5a, requiredResponses = RequiredResponses.CHALLENGE),
        GET(0x66, requiredResponses = RequiredResponses.THRESHOLD),
        COMMIT(0x99.toByte()),
        CHANGE(0xAA.toByte()),
        CHANGE_DKG(0xa0.toByte()),
        CHALLENGE_VERIFY(0xA5.toByte(), requiredResponses = RequiredResponses.CHALLENGE),
        WRITE(0xCC.toByte()), DELETE(0xFF.toByte());

        fun <T> connect(cs: CredentialStore, password: CharArray, id: Map<Server, ByteArray>,
                                realm: Realm,
                        body: ((Map<Server, Socket>, ByteArray, ByteArray) -> T)? = null): T? {
            val (r, alpha) = Oprf.blind(toBytes(password.clone())) // TODO only CREATE + GET?

            val requests = id.mapValues { entry ->
                val message = ByteBuffer.allocate(DECAF_255_SER_BYTES + CRYPTO_GENERICHASH_BYTES + 1)
                message.put(code)
                message.put(entry.value)
                message.put(alpha)
                message.array()
            }
            val s = performRateLimit(cs, requests)
            s.use { socket ->
                val responses = try {
                    socket.gather(
                        33 + ENCRYPTED_RULE_LENGTH,
                        cs.threshold
                    )
                } catch (_: IllegalStateException) {
                    throw ServerFailureException()
                }
                val rules = responses.values.map { it.sliceArray(33 until it.size) }
                val rule = rules.first()
                val beta = if (cs.servers.size > 1) {
                    Oprf.thresholdMult(responses.values.map { it.sliceArray(0 until 33) })
                } else {
                    responses.values.first().sliceArray(1 until 33).apply {
                        if (this contentEquals RESPONSE_FAIL) throw ServerFailureException()
                    }
                }
                val unblinded = Oprf.unblindFinalize(r, beta, toBytes(password.clone()))
                val rwd = realm.oprfToRwd(cs, unblinded!!)
                val result = body?.invoke(socket, rwd, rule)
                return result
            }
        }



        enum class RequiredResponses {
            ALL, THRESHOLD, CHALLENGE
        }

        fun execute(realm: Realm, password: CharArray, cs: CredentialStore,
                    createRule: Rule? = null): Pair<Rule, String> {
            val hostId = realm.hash(cs)
            return connect(cs, password, hostId, realm) { s, oldRwd, rule ->
                val newRwd = oldRwd

                val rule = if (createRule == null) {
                    val (_, ruleBytes) = cs.getSealKey().decrypt(rule)
                    Rule.parse(ruleBytes).apply {
                        if (checkDigit != calculateCheckDigit(newRwd).and(CHECK_DIGIT_MASK)) {
                            throw CheckDigitMismatchException()
                        }
                    }
                } else createRule.withCheckDigit(calculateCheckDigit(newRwd))

                rule to rule.derive(newRwd)
            }!!
        }


        fun performRateLimit(cs: CredentialStore, requests: Map<Server, ByteArray>): Map<Server, Socket> {
            val challenges = cs.createSocket().use { s ->
                val rr = when (requiredResponses) {
                    RequiredResponses.ALL -> s.size
                    RequiredResponses.THRESHOLD -> cs.threshold
                    RequiredResponses.CHALLENGE -> throw IllegalArgumentException("Invalid state")
                }
                s.sendCommand(CHALLENGE_CREATE, requests)
                s.gather(1 + 1 + 8 + 32, rr)
            }
            val puzzles = challenges.map { (server, challenge) ->
                val n = challenge[0]
                val k = challenge[1]
                val seed = challenge + requests[server]!!
                val solution = Equihash.solve(n.toInt(), k.toInt(), seed)!!
                server to (challenge to solution)
            }.toMap()
            val socket = puzzles.keys.createSocket()
            val parameters = puzzles.mapValues { entry -> entry.value.first + requests[entry.key]!! + entry.value.second }
            socket.sendCommand(CHALLENGE_VERIFY, parameters)
            return socket
        }

        fun serializeCommand(
            parts: Map<Server, ByteArray>,
        ): Map<Server, ByteArray> = parts.mapValues { entry ->
            val bb = ByteBuffer.allocate(1 + entry.value.size )
            bb.put(code)
            bb.put(entry.value)
            bb.array()
        }
    }

    data class Realm(val username: String, val hostname: String) {
        fun hash(cs: CredentialStore): Map<Server, ByteArray> {
            val commonPrefix = serializeUserHost()
            val commonPrefixSize = commonPrefix.size
            return cs.servers.associateWith { server ->
                val nameBytes = server.name.toByteArray()
                Sodium.genericHash(
                    ByteBuffer.allocate(commonPrefixSize + nameBytes.size + 2)
                        .order(ByteOrder.BIG_ENDIAN)
                        .put(commonPrefix)
                        .putShort(nameBytes.size.toShort())
                        .put(nameBytes)
                        .array(),
                    cs.key.foldHash(DerivationContext.SALT)
                )
            }
        }

        fun oprfToRwd(cs: CredentialStore, rwd: ByteArray): ByteArray {
            val salt = Sodium.genericHash(serializeUserHost(cs.key.foldHash(DerivationContext.SALT)),
                null, CRYPTO_PWHASH_SALTBYTES)
            return Sodium.passwordHash(OPRF_BYTES, rwd, salt)!!
        }

        private fun serializeUserHost(prefix: ByteArray? = null): ByteArray {
            val usernameBytes = username.toByteArray()
            val hostnameBytes = hostname.toByteArray()
            val commonPrefix = ByteBuffer.allocate(usernameBytes.size + hostnameBytes.size + 4 + (prefix?.size
                ?: 0))
            commonPrefix.order(ByteOrder.BIG_ENDIAN)
            if (prefix != null) commonPrefix.put(prefix)
            commonPrefix.putShort(usernameBytes.size.toShort())
            commonPrefix.put(usernameBytes)
            commonPrefix.putShort(hostnameBytes.size.toShort())
            commonPrefix.put(hostnameBytes)
            return commonPrefix.array()
        }

        val withoutUser: Realm
            get() = Realm(username = "", hostname = hostname)
    }

    class ServerFailureException : RuntimeException()
    class CheckDigitMismatchException : RuntimeException()

    interface CredentialStore {
        val key: MasterKey
        val servers: List<Server>
        val rwdKeys: Boolean
        val threshold: Int
    }

    data class Server(val name: String, val host: String, val port: Int, val longTermSignatureKey: ImmutableByteArray)

    companion object {

        fun create(password: CharArray, realm: Realm, charClasses: Set<CharacterClass>,
                   cs: CredentialStore, symbols: Set<Char>, size: Int = 0): String {
            require(charClasses.isNotEmpty() || symbols.isNotEmpty()) { "At least one character class or symbol must be allowed." } // TODO additional checks c.f. with_schema
            val baseRule = Rule(charClasses, symbols, size.toBigInteger(), BigInteger.ZERO)
            val (r, alpha) = Oprf.blind(toBytes(password.clone()))
            val hostId = realm.hash(cs)
            val (socket, beta) = if (cs.threshold > 1) {
                cs.dkg(Command.CREATE_DKG, hostId, alpha)
            } else {
                val s = cs.createSocket()
                val cmd = hostId[cs.servers.first()]!! + alpha
                s.broadcastToPeers(Command.CREATE.serializeCommand(cs.servers.associateWith { cmd }))
                val beta = s.gather(33).values.first()
                s to beta.sliceArray(1 until beta.size)
            }
            val unblinded = Oprf.unblindFinalize(r, beta, toBytes(password.clone()))
            val rwd = realm.oprfToRwd(cs, unblinded!!)
            val rule = baseRule.withXorMaskFor(rwd)
            cs.sendRule(socket, rule, rwd, hostId)
            updateUserList(socket, cs, realm) { users -> users + realm.username }
            return rule.derive(rwd)
        }

        fun calculateCheckDigit(rwd: ByteArray): BigInteger {
            return BigInteger(POSITIVE, DerivationContext.CHECK_DIGIT.foldHash(rwd))
        }

        fun get(password: CharArray, realm: Realm, cs: CredentialStore): Pair<Rule, String> {
            return Command.GET.execute(realm, password, cs)
        }

        fun change(password: CharArray, realm: Realm, charClasses: Set<CharacterClass>,
                   cs: CredentialStore, symbols: Set<Char>, size: Int = 0): String {
            // TODO add support for changing master password
            require(charClasses.isNotEmpty() || symbols.isNotEmpty()) { "At least one character class or symbol must be allowed." } // TODO additional checks c.f. with_schema
            // TODO add support for deterministic xorMask creation
            val baseRule = Rule(charClasses, symbols, size.toBigInteger(), BigInteger.ZERO)
            val (r, alpha) = Oprf.blind(toBytes(password.clone()))
            val hostId = realm.hash(cs)
            val cmd = hostId.mapValues { (_, id) -> id + alpha }
            val op = if (cs.threshold > 1) Command.CHANGE_DKG else Command.CHANGE
            val messages = op.serializeCommand(cmd)
            val socket = op.performRateLimit(cs, messages)
            cs.auth(socket, hostId, messages, AuthContext(alpha, password, r, realm))
            val (r2, alpha2) = Oprf.blind(toBytes(password.clone()))
            val beta2 = if (cs.threshold > 1) {
                cs.dkg(Command.CHANGE_DKG, hostId, alpha2, socket).second
            } else {
                socket.broadcastToPeers(cs.servers.associateWith { alpha2 })
                val b = socket.gather(33, 1)
                b.values.first().sliceArray(1 until 33)
            }
            val unblinded = Oprf.unblindFinalize(r2, beta2, toBytes(password.clone()))
            val rwd = realm.oprfToRwd(cs, unblinded!!)
            val rule = baseRule.withXorMaskFor(rwd)
            cs.sendRule(socket, rule, rwd, hostId)
            check(socket.gather(2).values.all(RESPONSE_OK::contentEquals),
                { "failed to update rules" })
            return rule.derive(rwd)
        }

        fun commit(password: CharArray, realm: Realm, cs: CredentialStore) {
            val (r, alpha) = Oprf.blind(toBytes(password.clone()))
            val hostId = realm.hash(cs)
            val cmd = hostId.mapValues { (_, id) -> id + alpha }
            val messages = Command.COMMIT.serializeCommand(cmd)
            val socket = Command.COMMIT.performRateLimit(cs, messages)
            cs.auth(socket, hostId, messages, AuthContext(alpha, password, r, realm))
            check(socket.gather(2).values.all(RESPONSE_OK::contentEquals),
                { "failed to update rules" })
            // TODO Command.COMMIT.connect<Void>(cs, password, realm.hash(cs))
        }

        fun undo(password: CharArray, realm: Realm, cs: CredentialStore) {
            val (r, alpha) = Oprf.blind(toBytes(password.clone()))
            val hostId = realm.hash(cs)
            val cmd = hostId.mapValues { (_, id) -> id + alpha }
            val messages = Command.UNDO.serializeCommand(cmd)
            val socket = Command.UNDO.performRateLimit(cs, messages)
            cs.auth(socket, hostId, messages, AuthContext(alpha, password, r, realm))
            check(socket.gather(2).values.all(RESPONSE_OK::contentEquals),
                { "failed to update rules" })
            // TODO Command.UNDO.connect<Void>(cs, password, realm.hash(cs))
        }

        fun delete(password: CharArray, realm: Realm, cs: CredentialStore) {
            val (r, alpha) = Oprf.blind(toBytes(password.clone()))
            val hostId = realm.hash(cs)
            val cmd = hostId.mapValues { (_, id) -> id + alpha }
            val messages = Command.DELETE.serializeCommand(cmd)
            val socket = Command.DELETE.performRateLimit(cs, messages)
            cs.auth(socket, hostId, messages, AuthContext(alpha, password, r, realm))
            updateUserList(socket, cs, realm) { users -> if (users.isEmpty()) null else users - realm.username }
            check(socket.gather(2).values.all(RESPONSE_OK::contentEquals),
                { "failed to update rules" })
            /* TODO Command.DELETE.connect(cs, password, realm.hash(cs)) { s, _ ->
                updateUserList(s, cs, realm) { users -> if (users.isEmpty()) null else users - realm.username }
            }*/
        }

        fun list(hostname: String, cs: CredentialStore): Set<String> {
            val realm = Realm(hostname = hostname, username = "")
            val hostId = realm.hash(cs)
            val request = Command.READ.serializeCommand(hostId)
            val socket = try {
                Command.READ.performRateLimit(cs, request)
            } catch (e: ServerFailureException) {
                return emptySet()
            }
            socket.use {
                try {
                    cs.auth(socket, hostId, request, null)
                } catch (e: ServerFailureException) {
                    return emptySet()
                }
                return receiveUsernameList(socket, cs.getSealKey()) ?: emptySet()
            }

            /*val hostId = Realm(hostname = hostname, username = "").hash(cs)
            val request = byteArrayOf(Command.READ.code) + hostId
            val socket = try {
                performRateLimit(cs, request)
            } catch (e: ServerFailureException) {
                return emptySet()
            }
            socket.use {
                try {
                    cs.auth(socket, hostId, ByteArray(0))
                } catch (e: ServerFailureException) {
                    return emptySet()
                }
                return receiveUsernameList(socket, cs.getSealKey()) ?: emptySet()
            }*/
            //return emptySet() // TODO
        }
    }
}

private fun Protocol.CredentialStore.dkg(
    operation: Protocol.Command,
    id: Map<Protocol.Server, ByteArray>?,
    alpha: ByteArray,
    authSocket: Map<Protocol.Server, Socket>? = null
): Pair<Map<Protocol.Server, Socket>, ByteArray> {
    val n = servers.size.toByte()
    val peerLongTermPublicKeys = servers.map { server ->
        check(
            server.longTermSignatureKey.isNotEmpty(),
            { "longTermSignatureKey for server ${server.name} is unset" })
        server.longTermSignatureKey.toMutableArray()
    }
    val socket = authSocket ?: createSocket()
    val tp = if (operation == Protocol.Command.CREATE_DKG) {
        val (tp, msg0) = Oprf.tpDkgStartTp(n, threshold.toByte(), TS_EPSILON,
            "threshold sphinx dkg create k", peerLongTermPublicKeys)
        val postfix = alpha + msg0
        socket.sendCommand(operation, id!!.mapValues { (_, hostId) ->
            hostId + postfix
        })
        tp
    } else {
        val (tp, msg0) = Oprf.tpDkgStartTp(n, threshold.toByte(), TS_EPSILON,
            "threshold sphinx dkg change k", peerLongTermPublicKeys)
        val message = alpha + msg0
        socket.broadcastToPeers(servers.associateWith { message })
        tp
    }
    tp.use {
        while (tp.isNotDone) {
            val (ret, sizes) = tp.inputSizes
            val peerMessages = if (ret) {
                if (sizes[0] > 0) socket.gather(sizes[0].toInt(), servers.size)
                else emptyMap()
            } else {
                socket.gather(sizes)
            }
            val bb = ByteBuffer.allocate(peerMessages.values.asSequence().map(ByteArray::size).sum())
            servers.forEach { bb.put(peerMessages[it] ?: return@forEach) }
            val out = tp.next(bb.array())!!
            if (out.isNotEmpty()) {
                val msg = servers.mapIndexed { i, server -> server to tp.peerMessage(out, i.toByte())!! }.toMap()
                socket.broadcastToPeers(msg)
            }
        }
    }
    val betas = socket.gather(33).values.toList()
    return socket to betas.permutations().map(Oprf::thresholdMult).toList().ensureMatchingByteArrays()
}

private fun Collection<ByteArray>.ensureMatchingByteArrays(): ByteArray {
    check(isNotEmpty(), { "list cannot be empty" })
    val first = first()
    if (size > 1) {
        check(asSequence().drop(1).all { it contentEquals first },
            { "disagreement among servers" })
    }
    return first
}

private fun Map<Protocol.Server, Socket>.gather(byteCount: Int, requiredResponses: Int = 0): Map<Protocol.Server, ByteArray> {
    val responses = this.entries.mapNotNull { (server, socket) ->
        try {
            server to socket.getInputStream().readExactly(byteCount)
        } catch (_: Exception) {
            null
        }
    }.toMap()
    val threshold = if (requiredResponses > 0) requiredResponses else this.size
    check(responses.size >= threshold,
        { "not enough responses gather($byteCount)ed: (${responses.size} < $threshold) $responses" })
    return responses
}

private fun Map<Protocol.Server, Socket>.gather(byteCounts: LongArray): Map<Protocol.Server, ByteArray> {
    val responses = this.entries.withIndex().mapNotNull { (i, entry) ->
        try {
            entry.key to entry.value.getInputStream().readExactly(byteCounts[i].toInt())
        } catch (_: Exception) {
            null
        }
    }.toMap()
    val threshold = this.size
    check(responses.size >= threshold,
        { "not enough responses gather(${byteCounts.asList()})ed: (${responses.size} < $threshold) $responses" })
    return responses
}

private fun Map<Protocol.Server, Socket>.sendCommand(command: Protocol.Command, parameters: Map<Protocol.Server, ByteArray>) {
    broadcastToPeers(command.serializeCommand(parameters))
}

private fun Map<Protocol.Server, Socket>.broadcastToPeers(
    messages: Map<Protocol.Server, ByteArray>
) {
    this.entries.forEach {
        entry -> entry.value.getOutputStream().write(messages[entry.key]) }
}

private fun updateUserList(socket: Map<Protocol.Server, Socket>, cs: Protocol.CredentialStore, realm: Protocol.Realm,
                           update: (Set<String>) -> Set<String>?) {
    val hostId = realm.withoutUser.hash(cs)
    socket.broadcastToPeers(hostId.mapValues { (_, id) ->
        id + cs.getSignKey(id).sign(id)
    })

    val sealKey = cs.getSealKey()
    val usernameList = receiveUsernameList(socket, sealKey)
    val users = update(usernameList ?: emptySet()) ?: return
    val plainText = users.joinToString("\u0000").toByteArray()

    socket.broadcastToPeers(hostId.mapValues { (_, id) ->
        val hostSk = cs.getSignKey(id)
        val encrypted = sealKey.encrypt(plainText)
        val payloadSize = encrypted.size
        check(payloadSize < 0x10000, { "list of usernames must be less than 64kB" })
        val envelope = if (usernameList == null) {
            ByteBuffer.allocate(CRYPTO_SIGN_PUBLICKEYBYTES + 2 + payloadSize).put(hostSk.publicKey)
        } else {
            ByteBuffer.allocate(2 + payloadSize)
        }.order(ByteOrder.BIG_ENDIAN)
        envelope.putShort(payloadSize.toShort())
        envelope.put(encrypted)
        val toSign = envelope.array()
        toSign + hostSk.sign(toSign)
    })
}

fun Sphinx.Challenge.finish(salt: ByteArray, stream: InputStream): ByteArray =
    finish(salt, stream.readExactly(DECAF_255_SER_BYTES)) ?: throw Protocol.ServerFailureException()

fun Protocol.CredentialStore.sendRule(socket: Map<Protocol.Server, Socket>, rule: Rule,
                                              newRwd: ByteArray, hostId: Map<Protocol.Server, ByteArray>) {
    val sealKey = getSealKey()
    val messages = socket.mapValues { (server, _) ->
        val signKey = getSignKey(hostId[server]!!, newRwd)
        val ruleCipherText = sealKey.encrypt(rule.serialize())
        val msg = signKey.publicKey + ruleCipherText
        msg + signKey.sign(msg)
    }
    socket.broadcastToPeers(messages)
}

private fun receiveUsernameList(socket: Map<Protocol.Server, Socket>, key: AeadKey): Set<String>? {
    val blobSizes = socket.readBE16() // TODO why not just cs.threshold?
    check(blobSizes.values.toSet().size == 1, { "servers disagree on userlist blob size" })
    val length = blobSizes.values.first()
    if (length == 0) return null
    val blobs = socket.gather(length)
    val plainTextBlobs = mutableSetOf<String>()
    for (blob in blobs.values) {
        if (blob contentEquals BLOB_FAIL) {
            throw Protocol.ServerFailureException()
        }
        plainTextBlobs.add(key.decrypt(blob).second.decodeToString())
    }
    check(plainTextBlobs.size == 1, { "servers disagree on userlist contents" })
    return plainTextBlobs.first().split('\u0000').toSortedSet()
}

private fun Map<Protocol.Server, Socket>.readBE16(): Map<Protocol.Server, Int> {
    val len = ByteArray(4) // avoid overflows, as JVM short is signed
    val bb = ByteBuffer.wrap(len).order(ByteOrder.BIG_ENDIAN)
    return mapValues { (server, socket) ->
        socket.getInputStream().read(len, 2, 2)
        bb.getInt(0)
    }
}

private fun InputStream.readExactly(length: Int): ByteArray {
    val buffer = ByteArray(length)
    if (read(buffer) != length) throw Protocol.ServerFailureException()
    return buffer
}

fun Protocol.CredentialStore.getSignKey(id: ByteArray, rwd: ByteArray? = null): Ed25519PrivateKey =
    Ed25519PrivateKey.fromSeed(key.foldHash(DerivationContext.SIGNING, id, if (rwdKeys) rwd else null))

fun Protocol.CredentialStore.getSealKey(): AeadKey =
    AeadKey.fromByteArray(key.foldHash(DerivationContext.ENCRYPTION))

class AuthContext(val alpha: ByteArray, val password: CharArray, val r: ByteArray, val realm: Protocol.Realm)

fun Protocol.CredentialStore.auth(
    socket: Map<Protocol.Server, Socket>, hostId: Map<Protocol.Server, ByteArray>,
    requests: Map<Protocol.Server, ByteArray>, context: AuthContext? = null
) {
    val (challenges, rwd) = if (context == null) {
        try {
            socket.gather(AUTH_NONCE_BYTES)
        } catch (_: IllegalStateException) {
            throw Protocol.ServerFailureException() // TODO why does this fail if READ command was sent with a non-existent hostId?
        } to ByteArray(0)
    } else {
        val messages = socket.gather(65)
        val beta = if (servers.size > 1) {
            Oprf.thresholdMult(messages.values.asSequence().windowed(threshold).first().map { it.sliceArray(0 until 33) })
        } else {
            messages.values.first().sliceArray(1 until 33)
        }
        val unblinded = Oprf.unblindFinalize(context.r, beta, toBytes(context.password.clone()))
        val rwd = context.realm.oprfToRwd(this, unblinded!!)
        messages.mapValues { (_, m) -> m.sliceArray(33 until m.size) } to rwd
    }

    val response = challenges.mapValues { (server, nonce) ->
        getSignKey(hostId[server]!!, rwd).sign(requests[server]!! + nonce)
    }
    socket.broadcastToPeers(response)
    val authResponse = socket.gather(6)
    if (!authResponse.values.all { it contentEquals RESPONSE_AUTH }) {
        throw Protocol.ServerFailureException()
    }
}

private fun Protocol.CredentialStore.createSocket(): Map<Protocol.Server, Socket> {
    return servers.createSocket()
}

private fun Iterable<Protocol.Server>.createSocket(): Map<Protocol.Server, Socket> =
    this.associateWith { srv -> SSLSocketFactory.getDefault().createSocket(srv.host, srv.port) }

@OptIn(ExperimentalContracts::class)
inline fun <T : Map<Protocol.Server, Socket>, R> T.use(block: (T) -> R): R {
    contract {
        callsInPlace(block, InvocationKind.EXACTLY_ONCE)
    }
    var exception: Throwable? = null
    try {
        return block(this)
    } catch (e: Throwable) {
        exception = e
        throw e
    } finally {
        this.forEach { (
            _, s) -> s.androsphinxCloseFinally(exception) }
    }
}

fun Closeable.androsphinxCloseFinally(cause: Throwable?): Unit = when {
    cause == null -> close()
    else ->
        try {
            close()
        } catch (closeException: Throwable) {
            cause.addSuppressed(closeException)
        }
}

private fun ByteArray.equalsString(other: String): Boolean = contentEquals(other.toByteArray())

fun generateRandomXorMask(): BigInteger = BigInteger(POSITIVE, Sodium.randomBytes(XOR_MASK_BYTES))