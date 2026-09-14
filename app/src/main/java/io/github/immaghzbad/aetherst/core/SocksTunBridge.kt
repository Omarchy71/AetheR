package io.github.immaghzbad.aetherst.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.OsConstants
import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.RoutingMode
import io.github.immaghzbad.aetherst.shared.model.SocksReadiness
import java.io.BufferedOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

sealed interface FlowKey

data class FlowKey4(
    val proto: Int,
    val srcIp: Int,
    val srcPort: Int,
    val dstIp: Int,
    val dstPort: Int
) : FlowKey

data class FlowKey6(
    val proto: Int,
    val srcIp: ByteArray,
    val srcPort: Int,
    val dstIp: ByteArray,
    val dstPort: Int
) : FlowKey {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is FlowKey6) return false
        return proto == other.proto &&
                srcIp.contentEquals(other.srcIp) &&
                srcPort == other.srcPort &&
                dstIp.contentEquals(other.dstIp) &&
                dstPort == other.dstPort
    }

    override fun hashCode(): Int {
        var result = proto
        result = 31 * result + srcIp.contentHashCode()
        result = 31 * result + srcPort
        result = 31 * result + dstIp.contentHashCode()
        result = 31 * result + dstPort
        return result
    }
}

interface TunBridgeControl {
    fun start()
    fun stop()
    fun getStats(): SocksTunBridge.Stats
    fun updateUpstream(host: String, port: Int)
}

class SocksTunBridge(
    private val vpnService: VpnService,
    private val tunDescriptor: ParcelFileDescriptor,
    @Volatile private var socksHost: String = "127.0.0.1",
    @Volatile private var socksPort: Int = 1819,
    private val mtu: Int = 1280,
    private val blockedPackagesProvider: () -> Set<String>,
    private val routingEngine: RoutingEngine
) : TunBridgeControl {
    data class Stats(val txBytes: Long = 0, val rxBytes: Long = 0, val txDropped: Long = 0, val rxDropped: Long = 0, val tcpActive: Int = 0, val udpActive: Int = 0, val rejected: Long = 0)

    private enum class TcpState { SYN_RCVD, POLICY, CONNECTING, ESTABLISHED, CLOSING }

    private val isRunning = AtomicBoolean(false)
    private var readThread: Thread? = null
    private var writeThread: Thread? = null
    private companion object {
        private const val UDP_IDLE_SHORT = 60000L
        private const val UDP_IDLE_VOIP = 180000L
        private const val TCP_IDLE_MS = 120000L
        private const val MAX_PENDING_SESSIONS = 512
        private const val MAX_TCP_SESSIONS = 2048
        private const val TUN_QUEUE_CAP = 8192
        private const val SNI_WAIT_MS = 250L
        private const val CONNECT_WARMUP_MS = 1500
        private const val CONNECT_READY_MS = 4000
        private const val BLOCK_CACHE_TTL_MS = 300000L
        private fun isVoipPort(port: Int) = port in 3478..3480 || port >= 1024
    }
    private val bridgeScope = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(64))
    private val pendingSessions = AtomicLong(0)
    private val rejectedCount = AtomicLong(0)
    private val fastGateRst = AtomicLong(0)
    private val fastGateDrop = AtomicLong(0)
    private val blockRstCount = AtomicLong(0)
    private val blockNxCount = AtomicLong(0)
    private val tunDropCount = AtomicLong(0)
    private val sessDropCount = AtomicLong(0)
    private val tunnelFlowCount = AtomicLong(0)
    private val directFlowCount = AtomicLong(0)
    private val lastSummaryAt = AtomicLong(0)
    private val blockCache = ConcurrentHashMap<String, Long>()
    @Volatile
    private var lastGateSeen: SocksReadiness? = null
    private fun launchSession(key: FlowKey, isTcp: Boolean, onRst: () -> Unit, block: suspend () -> Unit) {
        pendingSessions.incrementAndGet()
        if (pendingSessions.get() > MAX_PENDING_SESSIONS) {
            pendingSessions.decrementAndGet()
            evictIdleSessions()
            if (pendingSessions.get() >= MAX_PENDING_SESSIONS) {
                val c = rejectedCount.incrementAndGet()
                if (c <= 5 || c % 50 == 0L) LogRepository.w("[TunBridge] shed new flow tcp=${tcpSessions.size} udp=${udpSessions.size} count=$c")
                if (isTcp) removeTcpKey(key) else removeUdpKey(key)
                onRst()
                return
            }
        }
        try {
            bridgeScope.launch {
                try {
                    block()
                } catch (_: Exception) {
                } finally {
                    pendingSessions.decrementAndGet()
                }
            }
        } catch (_: Exception) {
            pendingSessions.decrementAndGet()
            if (isTcp) removeTcpKey(key) else removeUdpKey(key)
            onRst()
            return
        }
    }
    private fun removeTcpKey(key: FlowKey) {
        tcpSessions.remove(key)?.forceClose()
        uidCache.remove(key)
    }
    private fun removeUdpKey(key: FlowKey) {
        udpSessions.remove(key)?.forceClose()
        uidCache.remove(key)
    }
    private fun evictIdleSessions() {
        if (tcpSessions.size < MAX_TCP_SESSIONS && udpSessions.size < MAX_TCP_SESSIONS) return
        val now = SystemClock.elapsedRealtime()
        var evicted = 0
        for ((k, s) in tcpSessions.entries) {
            if (evicted >= 64) break
            if (!s.isActiveFlow(now) && tcpSessions.remove(k, s)) {
                s.forceClose()
                evicted++
            }
        }
        for ((k, s) in udpSessions.entries) {
            if (evicted >= 128) break
            if (!s.isActiveFlow(now) && udpSessions.remove(k, s)) {
                s.forceClose()
                evicted++
            }
        }
        if (evicted > 0) LogRepository.i("[TunBridge] evict idle=$evicted tcp=${tcpSessions.size} udp=${udpSessions.size}")
    }
    private val tunOutputQueue = LinkedBlockingQueue<ByteArray>(TUN_QUEUE_CAP)
    private val tcpSessions = ConcurrentHashMap<FlowKey, TcpSession>()
    private val udpSessions = ConcurrentHashMap<FlowKey, UdpSession>()
    private val connectivityManager by lazy { vpnService.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager }
    private val connectionOwnerResolver by lazy { ConnectionOwnerResolver(connectivityManager) }
    private val dnsResolver = LocalDnsResolver(vpnService, socksHost, socksPort)
    private val packageManager by lazy { vpnService.packageManager }
    private val txBytes = AtomicLong(0)
    private val rxBytes = AtomicLong(0)
    private val dnsQueryCounter = AtomicLong(0)
    private val dnsResponseCounter = AtomicLong(0)

    @Volatile
    private var cachedBlockedPackages: Set<String> = emptySet()

    @Volatile
    private var cachedBlockedUids: Set<Int> = emptySet()

    @Volatile
    private var cachedUnderlyingNetwork: Network? = null
    @Volatile
    private var cachedUnderlyingNetworkAt: Long = 0L
    private val underlyingNetworkTtlMs = 2000L

    private data class IPv6Transport(
        val nextHeader: Int,
        val offset: Int
    )

    private data class SocksAddress(
        val address: InetAddress,
        val port: Int
    )

    override fun start() {
        if (isRunning.getAndSet(true)) return

        LogRepository.i("Initializing tunnel bridge (MTU=$mtu socks=$socksHost:$socksPort gate=${SocksGate.readiness.value})...")

        writeThread = Thread({
            val fos = FileOutputStream(tunDescriptor.fileDescriptor)
            while (isRunning.get()) {
                try {
                    val packet = tunOutputQueue.poll(500, TimeUnit.MILLISECONDS) ?: continue
                    fos.write(packet)
                    rxBytes.addAndGet(packet.size.toLong())
                } catch (_: InterruptedException) {
                    break
                } catch (e: Exception) {
                    LogRepository.w("TUN write error: ${e.message}")
                    if (!isRunning.get()) break
                }
            }
        }, "Aether-TunWriter").apply {
            isDaemon = true
            start()
        }

        readThread = Thread({
            val fis = FileInputStream(tunDescriptor.fileDescriptor)
            val buffer = ByteArray(mtu + 200)
            while (isRunning.get()) {
                try {
                    val n = fis.read(buffer)
                    if (n <= 0) continue
                    txBytes.addAndGet(n.toLong())
                    processPacket(buffer, n)
                } catch (e: Exception) {
                    if (isRunning.get()) LogRepository.w("TUN read error: ${e.message}")
                }
            }
        }, "Aether-TunReader").apply {
            isDaemon = true
            start()
        }
    }

    override fun stop() {
        if (!isRunning.getAndSet(false)) return
        bridgeScope.cancel()
        tcpSessions.values.forEach { it.forceClose() }
        tcpSessions.clear()
        udpSessions.values.forEach { it.forceClose() }
        udpSessions.clear()
        tunOutputQueue.clear()
        associatePool.reset()
        dnsResolver.shutdown()
        readThread?.interrupt()
        writeThread?.interrupt()
    }

    override fun getStats(): Stats = Stats(txBytes.get(), rxBytes.get(), tunDropCount.get(), sessDropCount.get(), tcpSessions.size, udpSessions.size, rejectedCount.get())

    override fun updateUpstream(host: String, port: Int) {
        socksHost = host
        socksPort = port
        runCatching { dnsResolver.updateUpstream(host, port) }
        associatePool.onUpstreamChanged()
        LogRepository.i("[TunBridge] Upstream switched to $host:$port mtu=$mtu gate=${SocksGate.readiness.value} activeTcp=${tcpSessions.size} activeUdp=${udpSessions.size}")
    }

    private fun enqueueTun(data: ByteArray, critical: Boolean = false) {
        if (critical) {
            if (!tunOutputQueue.offer(data)) {
                tunOutputQueue.poll()
                if (!tunOutputQueue.offer(data)) tunDropCount.incrementAndGet()
            }
        } else {
            if (!tunOutputQueue.offer(data)) tunDropCount.incrementAndGet()
        }
    }
    private fun gateReady(): Boolean = SocksGate.readiness.value == SocksReadiness.PROBED_OK
    private fun noteGate() {
        val g = SocksGate.readiness.value
        val prev = lastGateSeen
        if (prev != g) {
            lastGateSeen = g
            LogRepository.i("[TunBridge] gate $prev -> $g tcp=${tcpSessions.size} udp=${udpSessions.size} rej=${rejectedCount.get()} drop=${tunDropCount.get()}")
        }
    }
    private fun connectTimeoutMs(): Int = if (gateReady()) CONNECT_READY_MS else CONNECT_WARMUP_MS
    private fun blockKey(ip: String, port: Int, domain: String?): String {
        val n = domain?.trim()?.trimEnd('.')?.lowercase() ?: ""
        return "$ip:$port:$n"
    }
    private fun isBlockCached(ip: String, port: Int, domain: String?): Boolean {
        val n = domain?.trim()?.trimEnd('.')?.lowercase() ?: ""
        if (n.isEmpty()) return false
        val exp = blockCache[blockKey(ip, port, n)] ?: return false
        if (SystemClock.elapsedRealtime() > exp) {
            blockCache.remove(blockKey(ip, port, n))
            return false
        }
        return true
    }
    private fun cacheBlock(ip: String, port: Int, domain: String?) {
        val n = domain?.trim()?.trimEnd('.')?.lowercase() ?: ""
        if (n.isEmpty()) return
        blockCache[blockKey(ip, port, n)] = SystemClock.elapsedRealtime() + BLOCK_CACHE_TTL_MS
        if (blockCache.size > 2048) {
            val it = blockCache.entries.iterator()
            if (it.hasNext()) {
                it.next()
                it.remove()
            }
        }
    }
    private fun fastClassify(ip: String, port: Int, domain: String?): RoutingMode {
        if (isBlockCached(ip, port, domain)) return RoutingMode.BLOCK
        val d = routingEngine.resolve(ip, port, domain, null, null)
        if (d.mode == RoutingMode.BLOCK) cacheBlock(ip, port, d.resolvedDomain ?: domain)
        return d.mode
    }
    private fun maybeSummary() {
        val now = SystemClock.elapsedRealtime()
        if (now - lastSummaryAt.get() < 30000) return
        lastSummaryAt.set(now)
        LogRepository.i("[TunBridge] sum gate=${SocksGate.readiness.value} tcp=${tcpSessions.size} udp=${udpSessions.size} pend=${pendingSessions.get()} rst=${blockRstCount.get()} gateRst=${fastGateRst.get()} gateDrop=${fastGateDrop.get()} nx=${blockNxCount.get()} tunDrop=${tunDropCount.get()} sessDrop=${sessDropCount.get()} rej=${rejectedCount.get()} tun=${tunnelFlowCount.get()} dir=${directFlowCount.get()} assocRe=${associatePool.reuseCount.get()} assocNew=${associatePool.establishCount.get()}")
    }

    private val associatePool = SharedAssociatePool()
    private inner class SharedAssociatePool {
        private val lock = Any()
        private var ctrl: Socket? = null
        private var relay: InetSocketAddress? = null
        private var upstreamKey: String = ""
        val reuseCount = AtomicLong(0)
        val establishCount = AtomicLong(0)
        @Volatile
        var multiplexUnsupported: Boolean = false
        fun relayFor(): InetSocketAddress? {
            if (multiplexUnsupported) return null
            synchronized(lock) {
                val key = "$socksHost:$socksPort"
                val c = ctrl
                val r = relay
                if (c != null && r != null && key == upstreamKey && !c.isClosed && c.isConnected) {
                    reuseCount.incrementAndGet()
                    return r
                }
                runCatching { ctrl?.close() }
                ctrl = null
                relay = null
                val s = Socket()
                if (!vpnService.protect(s)) {
                    runCatching { s.close() }
                    return null
                }
                s.tcpNoDelay = true
                s.keepAlive = true
                try {
                    s.connect(InetSocketAddress(socksHost, socksPort), connectTimeoutMs())
                } catch (_: Exception) {
                    runCatching { s.close() }
                    return null
                }
                val ins = s.getInputStream()
                val out = s.getOutputStream()
                if (!socksHandshake(ins, out)) {
                    runCatching { s.close() }
                    multiplexUnsupported = true
                    LogRepository.w("[TunBridge] assoc shared handshake rejected, per-flow fallback")
                    return null
                }
                out.write(socksRequest(3, null, ByteArray(4), 0))
                out.flush()
                val rep = readSocksReply(ins)
                if (rep == null) {
                    runCatching { s.close() }
                    multiplexUnsupported = true
                    LogRepository.w("[TunBridge] assoc shared reply rejected, per-flow fallback")
                    return null
                }
                val host = if (rep.address.isAnyLocalAddress) runCatching { InetAddress.getByName(socksHost) }.getOrNull() ?: rep.address else rep.address
                val addr = InetSocketAddress(host, rep.port)
                ctrl = s
                relay = addr
                upstreamKey = key
                establishCount.incrementAndGet()
                if (establishCount.get() <= 3 || establishCount.get() % 25 == 0L) LogRepository.i("[TunBridge] assoc shared established relay=$addr via $key re=${reuseCount.get()}")
                return addr
            }
        }
        fun reset() {
            synchronized(lock) {
                runCatching { ctrl?.close() }
                ctrl = null
                relay = null
                upstreamKey = ""
            }
        }
        fun onUpstreamChanged() {
            synchronized(lock) {
                runCatching { ctrl?.close() }
                ctrl = null
                relay = null
                upstreamKey = ""
                multiplexUnsupported = false
            }
        }
    }
    private fun processPacket(packet: ByteArray, len: Int) {
        noteGate()
        if (len < 1) return
        when ((packet[0].toInt() and 0xF0) shr 4) {
            4 -> processIpv4(packet, len)
            6 -> processIpv6(packet, len)
        }
    }

    private fun processIpv4(packet: ByteArray, len: Int) {
        if (len < 20) return
        val proto = packet[9].toInt() and 0xFF
        if (proto != 6 && proto != 17) return

        val hLen = (packet[0].toInt() and 0x0F) * 4
        if (len < hLen) return

        val srcIp = getInt(packet, 12)
        val dstIp = getInt(packet, 16)

        if (proto == 6) {
            if (len < hLen + 20) return

            val srcPort = getShort(packet, hLen)
            val dstPort = getShort(packet, hLen + 2)
            val key = FlowKey4(6, srcIp, srcPort, dstIp, dstPort)
            val session = tcpSessions[key]

            if (session != null) {
                val flags = packet[hLen + 13].toInt() and 0xFF
                val isPureSyn = (flags and 0x02) != 0 && (flags and 0x10) == 0

                if (isPureSyn && !session.isConnected()) {
                    return
                } else {
                    if (isUidBlocked(session.uid)) {
                        tcpSessions.remove(key, session)
                        session.close()
                        return
                    }

                    val seq = getLong(packet, hLen + 4)
                    val tcpDataOffset = hLen + ((packet[hLen + 12].toInt() and 0xF0) shr 2)
                    val payloadLen = if (len > tcpDataOffset) len - tcpDataOffset else 0
                    val payload = if (payloadLen > 0) packet.copyOfRange(tcpDataOffset, len) else null

                    session.handleFromTun(seq, getLong(packet, hLen + 8), payload, flags)
                    return
                }
            }

            val flags = packet[hLen + 13].toInt() and 0xFF
            if ((flags and 0x02) != 0 && (flags and 0x10) == 0) {
                val srcBytes = intToBytes(srcIp)
                val dstBytes = intToBytes(dstIp)
                val local = InetSocketAddress(InetAddress.getByAddress(srcBytes), srcPort)
                val remote = InetSocketAddress(InetAddress.getByAddress(dstBytes), dstPort)
                val uid = resolveOwnerUid(key, OsConstants.IPPROTO_TCP, local, remote)

                if (uid == -1) {
                    if (currentBlockedUids().isNotEmpty()) {
                        LogRepository.d("[TunBridge] UID unresolved for ${local.address.hostAddress}:$srcPort->${remote.address.hostAddress}:$dstPort proto=TCP; holding for retransmit")
                        return
                    }
                    LogRepository.w("Flow owner UID unresolved; permitting connection")
                }

                if (isUidBlocked(uid)) {
                    val seq = getLong(packet, hLen + 4)
                    enqueueTun(buildTcp4(dstIp, srcIp, dstPort, srcPort, null, 0, (seq + 1) and 0xFFFFFFFFL, 0x14), true)
                    return
                }
                val dstIpStr = InetAddress.getByAddress(dstBytes).hostAddress ?: ""
                if (fastClassify(dstIpStr, dstPort, DnsMap.get(dstIpStr)) == RoutingMode.BLOCK) {
                    val seq = getLong(packet, hLen + 4)
                    enqueueTun(buildTcp4(dstIp, srcIp, dstPort, srcPort, null, 0, (seq + 1) and 0xFFFFFFFFL, 0x14), true)
                    blockRstCount.incrementAndGet()
                    maybeSummary()
                    return
                }
                if (!gateReady()) {
                    val seq = getLong(packet, hLen + 4)
                    enqueueTun(buildTcp4(dstIp, srcIp, dstPort, srcPort, null, 0, (seq + 1) and 0xFFFFFFFFL, 0x14), true)
                    fastGateRst.incrementAndGet()
                    maybeSummary()
                    return
                }
                val seq = getLong(packet, hLen + 4)
                val newSession = TcpSession(key, 4, srcBytes, dstBytes, srcPort, dstPort, seq, uid)
                val prev = tcpSessions.putIfAbsent(key, newSession)
                if (prev != null) return
                launchSession(key, true, {
                    val s = getLong(packet, hLen + 4)
                    enqueueTun(buildTcp4(dstIp, srcIp, dstPort, srcPort, null, 0, (s + 1) and 0xFFFFFFFFL, 0x14), true)
                }) { newSession.run() }
                maybeSummary()
            }
        } else {
            if (len < hLen + 8) return

            val srcPort = getShort(packet, hLen)
            val dstPort = getShort(packet, hLen + 2)

            if (dstPort == 53) {
                val payload = packet.copyOfRange(hLen + 8, len)
                val domain = extractDomainName(payload, payload.size)
                val dstIpStr = InetAddress.getByAddress(packet.copyOfRange(16, 20)).hostAddress ?: ""
                logDnsQuery(domain, dstIpStr)
                if (domain != null && routingEngine.resolve(dstIpStr, 53, domain, null, null).mode == RoutingMode.BLOCK) {
                    LogRepository.i("[DnsGuard] [Block] domain=$domain", "DnsGuard")
                    blockNxCount.incrementAndGet()
                    val nxResponse = buildDnsNXResponse(payload)
                    if (nxResponse != null) {
                        enqueueTun(buildUdp4(dstIp, srcIp, 53, srcPort, nxResponse), true)
                        return
                    }
                }
                if (!gateReady()) {
                    fastGateDrop.incrementAndGet()
                    maybeSummary()
                    return
                }
                val q = payload
                val srv = dstIpStr
                launchSession(FlowKey4(17, srcIp, srcPort, dstIp, dstPort), false, {}) {
                    val response = dnsResolver.resolve(q, srv)
                    if (response != null) {
                        sniffDnsResponse(response)
                        enqueueTun(buildUdp4(dstIp, srcIp, 53, srcPort, response), true)
                        logDnsResponse()
                    }
                }
                return
            }

            if (srcPort == 53) {
                val payload = packet.copyOfRange(hLen + 8, len)
                sniffDnsResponse(payload)
            }

            dispatchUdp4(FlowKey4(17, srcIp, srcPort, dstIp, dstPort), srcIp, dstIp, srcPort, dstPort, packet.copyOfRange(hLen + 8, len))
        }
    }

    private fun dispatchUdp4(
        key: FlowKey4,
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ) {
        val session = udpSessions[key]

        if (session != null) {
            if (isUidBlocked(session.uid)) {
                udpSessions.remove(key, session)
                session.forceClose()
                return
            }
            if (!session.queue(payload)) sessDropCount.incrementAndGet()
            return
        }
        if (!gateReady()) {
            fastGateDrop.incrementAndGet()
            maybeSummary()
            return
        }
        val srcBytes = intToBytes(srcIp)
        val dstBytes = intToBytes(dstIp)
        val dstIpStr = InetAddress.getByAddress(dstBytes).hostAddress ?: ""
        if (fastClassify(dstIpStr, dstPort, DnsMap.get(dstIpStr)) == RoutingMode.BLOCK) {
            blockRstCount.incrementAndGet()
            maybeSummary()
            return
        }
        val local = InetSocketAddress(InetAddress.getByAddress(srcBytes), srcPort)
        val remote = InetSocketAddress(InetAddress.getByAddress(dstBytes), dstPort)
        val uid = resolveOwnerUid(key, OsConstants.IPPROTO_UDP, local, remote)

        if (uid == -1) {
            if (currentBlockedUids().isNotEmpty()) {
                LogRepository.d("[TunBridge] UID unresolved for ${local.address.hostAddress}:$srcPort->${remote.address.hostAddress}:$dstPort proto=UDP; holding for next datagram")
                return
            }
            LogRepository.w("Flow owner UID unresolved; permitting connection")
        }

        if (isUidBlocked(uid)) return

        val newSession = UdpSession(key, 4, srcBytes, dstBytes, srcPort, dstPort, uid)
        val prev = udpSessions.putIfAbsent(key, newSession)
        if (prev != null) {
            if (!prev.queue(payload)) sessDropCount.incrementAndGet()
            return
        }
        if (!newSession.queue(payload)) sessDropCount.incrementAndGet()
        launchSession(key, false, {}) { newSession.run() }
        maybeSummary()
    }

    private fun processIpv6(packet: ByteArray, len: Int) {
        val transport = ipv6Transport(packet, len) ?: return
        val srcIp = packet.copyOfRange(8, 24)
        val dstIp = packet.copyOfRange(24, 40)
        val offset = transport.offset

        if (len < offset + 4) return

        val srcPort = getShort(packet, offset)
        val dstPort = getShort(packet, offset + 2)

        if (transport.nextHeader == 6) {
            if (len < offset + 20) return

            val key = FlowKey6(6, srcIp, srcPort, dstIp, dstPort)
            val session = tcpSessions[key]

            if (session != null) {
                val flags = packet[offset + 13].toInt() and 0xFF
                val isPureSyn = (flags and 0x02) != 0 && (flags and 0x10) == 0

                if (isPureSyn && !session.isConnected()) {
                    return
                } else {
                    if (isUidBlocked(session.uid)) {
                        tcpSessions.remove(key, session)
                        session.close()
                        return
                    }

                    val seq = getLong(packet, offset + 4)
                    val tcpDataOffset = offset + ((packet[offset + 12].toInt() and 0xF0) shr 2)
                    val payloadLen = if (len > tcpDataOffset) len - tcpDataOffset else 0
                    val payload = if (payloadLen > 0) packet.copyOfRange(tcpDataOffset, len) else null

                    session.handleFromTun(seq, getLong(packet, offset + 8), payload, flags)
                    return
                }
            }

            val flags = packet[offset + 13].toInt() and 0xFF
            if ((flags and 0x02) != 0 && (flags and 0x10) == 0) {
                val local = InetSocketAddress(InetAddress.getByAddress(srcIp), srcPort)
                val remote = InetSocketAddress(InetAddress.getByAddress(dstIp), dstPort)
                val uid = resolveOwnerUid(key, OsConstants.IPPROTO_TCP, local, remote)

                if (uid == -1) {
                    if (currentBlockedUids().isNotEmpty()) {
                        LogRepository.d("[TunBridge] UID unresolved for ${local.address.hostAddress}:$srcPort->${remote.address.hostAddress}:$dstPort proto=TCP; holding for retransmit")
                        return
                    }
                    LogRepository.w("Flow owner UID unresolved; permitting connection")
                }

                if (isUidBlocked(uid)) {
                    val seq = getLong(packet, offset + 4)
                    enqueueTun(buildTcp6(dstIp, srcIp, dstPort, srcPort, null, 0, (seq + 1) and 0xFFFFFFFFL, 0x14), true)
                    return
                }
                val dstIpStr = InetAddress.getByAddress(dstIp).hostAddress ?: ""
                if (fastClassify(dstIpStr, dstPort, DnsMap.get(dstIpStr)) == RoutingMode.BLOCK) {
                    val seq = getLong(packet, offset + 4)
                    enqueueTun(buildTcp6(dstIp, srcIp, dstPort, srcPort, null, 0, (seq + 1) and 0xFFFFFFFFL, 0x14), true)
                    blockRstCount.incrementAndGet()
                    maybeSummary()
                    return
                }
                if (!gateReady()) {
                    val seq = getLong(packet, offset + 4)
                    enqueueTun(buildTcp6(dstIp, srcIp, dstPort, srcPort, null, 0, (seq + 1) and 0xFFFFFFFFL, 0x14), true)
                    fastGateRst.incrementAndGet()
                    maybeSummary()
                    return
                }
                val seq = getLong(packet, offset + 4)
                val newSession = TcpSession(key, 6, srcIp, dstIp, srcPort, dstPort, seq, uid)
                val prev = tcpSessions.putIfAbsent(key, newSession)
                if (prev != null) return
                launchSession(key, true, {
                    val s = getLong(packet, offset + 4)
                    enqueueTun(buildTcp6(dstIp, srcIp, dstPort, srcPort, null, 0, (s + 1) and 0xFFFFFFFFL, 0x14), true)
                }) { newSession.run() }
                maybeSummary()
            }
        } else if (transport.nextHeader == 17) {
            if (len < offset + 8) return

            if (dstPort == 53) {
                val payload = packet.copyOfRange(offset + 8, len)
                val domain = extractDomainName(payload, payload.size)
                val dstIpStr = InetAddress.getByAddress(packet.copyOfRange(24, 40)).hostAddress ?: ""
                logDnsQuery(domain, dstIpStr)
                if (domain != null && routingEngine.resolve(dstIpStr, 53, domain, null, null).mode == RoutingMode.BLOCK) {
                    LogRepository.i("[DnsGuard] [Block] domain=$domain", "DnsGuard")
                    blockNxCount.incrementAndGet()
                    val nxResponse = buildDnsNXResponse(payload)
                    if (nxResponse != null) {
                        enqueueTun(buildUdp6(dstIp, srcIp, 53, srcPort, nxResponse), true)
                        return
                    }
                }
                if (!gateReady()) {
                    fastGateDrop.incrementAndGet()
                    maybeSummary()
                    return
                }
                val q = payload
                val srv = dstIpStr
                launchSession(FlowKey6(17, srcIp, srcPort, dstIp, dstPort), false, {}) {
                    val response = dnsResolver.resolve(q, srv)
                    if (response != null) {
                        sniffDnsResponse(response)
                        enqueueTun(buildUdp6(dstIp, srcIp, 53, srcPort, response), true)
                        logDnsResponse()
                    }
                }
                return
            }

            if (srcPort == 53) {
                val payload = packet.copyOfRange(offset + 8, len)
                sniffDnsResponse(payload)
            }

            dispatchUdp6(FlowKey6(17, srcIp, srcPort, dstIp, dstPort), srcIp, dstIp, srcPort, dstPort, packet.copyOfRange(offset + 8, len))
        }
    }

    private fun dispatchUdp6(
        key: FlowKey6,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ) {
        val session = udpSessions[key]

        if (session != null) {
            if (isUidBlocked(session.uid)) {
                udpSessions.remove(key, session)
                session.forceClose()
                return
            }
            if (!session.queue(payload)) sessDropCount.incrementAndGet()
            return
        }
        if (!gateReady()) {
            fastGateDrop.incrementAndGet()
            maybeSummary()
            return
        }
        val dstIpStr = InetAddress.getByAddress(dstIp).hostAddress ?: ""
        if (fastClassify(dstIpStr, dstPort, DnsMap.get(dstIpStr)) == RoutingMode.BLOCK) {
            blockRstCount.incrementAndGet()
            maybeSummary()
            return
        }
        val local = InetSocketAddress(InetAddress.getByAddress(srcIp), srcPort)
        val remote = InetSocketAddress(InetAddress.getByAddress(dstIp), dstPort)
        val uid = resolveOwnerUid(key, OsConstants.IPPROTO_UDP, local, remote)

        if (uid == -1) {
            if (currentBlockedUids().isNotEmpty()) {
                LogRepository.d("[TunBridge] UID unresolved for ${local.address.hostAddress}:$srcPort->${remote.address.hostAddress}:$dstPort proto=UDP; holding for next datagram")
                return
            }
            LogRepository.w("Flow owner UID unresolved; permitting connection")
        }

        if (isUidBlocked(uid)) return

        val newSession = UdpSession(key, 6, srcIp, dstIp, srcPort, dstPort, uid)
        val prev = udpSessions.putIfAbsent(key, newSession)
        if (prev != null) {
            if (!prev.queue(payload)) sessDropCount.incrementAndGet()
            return
        }
        if (!newSession.queue(payload)) sessDropCount.incrementAndGet()
        launchSession(key, false, {}) { newSession.run() }
        maybeSummary()
    }

    private fun ipv6Transport(packet: ByteArray, len: Int): IPv6Transport? {
        if (len < 40) return null
        var nextHeader = packet[6].toInt() and 0xFF
        var offset = 40

        while (true) {
            when (nextHeader) {
                6, 17 -> return IPv6Transport(nextHeader, offset)
                0, 43, 60, 135 -> {
                    if (offset + 2 > len) return null
                    val extLen = ((packet[offset + 1].toInt() and 0xFF) + 1) * 8
                    nextHeader = packet[offset].toInt() and 0xFF
                    offset += extLen
                }
                44 -> return null
                else -> return null
            }
        }
    }

    private fun logDnsQuery(domain: String?, serverIp: String) {
        val n = dnsQueryCounter.incrementAndGet()
        if (n <= 5 || n % 25 == 0L) {
            LogRepository.i("[DnsGuard] DNS query #$n domain=${domain ?: "?"} server=$serverIp")
        }
    }

    private fun logDnsResponse() {
        val n = dnsResponseCounter.incrementAndGet()
        if (n <= 5 || n % 25 == 0L) {
            LogRepository.i("[DnsGuard] DNS response #$n written to TUN")
        }
    }

    private fun ownerUid(protocol: Int, local: InetSocketAddress, remote: InetSocketAddress): Int {
        return connectionOwnerResolver.resolve(protocol, local, remote)
    }

    private val uidCache = ConcurrentHashMap<FlowKey, Int>()

    private fun resolveOwnerUid(key: FlowKey, protocol: Int, local: InetSocketAddress, remote: InetSocketAddress): Int {
        uidCache[key]?.let { return it }
        val uid = ownerUid(protocol, local, remote)
        if (uid != -1) uidCache[key] = uid
        return uid
    }

    @Suppress("DEPRECATION")
    private fun underlyingNetwork(): Network? {
        val now = SystemClock.elapsedRealtime()
        val cached = cachedUnderlyingNetwork
        if (cached != null && now - cachedUnderlyingNetworkAt < underlyingNetworkTtlMs) {
            val caps = connectivityManager.getNetworkCapabilities(cached)
            if (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return cached
        }
        val candidates = connectivityManager.allNetworks.filter { network ->
            val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return@filter false
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }
        val result = candidates.firstOrNull { network ->
            connectivityManager.getNetworkCapabilities(network)
                ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        } ?: candidates.firstOrNull()
        cachedUnderlyingNetwork = result
        cachedUnderlyingNetworkAt = now
        return result
    }

    private fun supportsIpv6(network: Network): Boolean {
        return connectivityManager.getLinkProperties(network)?.routes?.any { route ->
            route.isDefaultRoute && route.destination.address is Inet6Address
        } == true
    }

    private fun supportsIpv4(network: Network): Boolean {
        return connectivityManager.getLinkProperties(network)?.routes?.any { route ->
            route.isDefaultRoute && route.destination.address is java.net.Inet4Address
        } == true
    }

    private fun networkLabel(network: Network): String {
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return "physical"
        return when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "physical"
        }
    }

    private fun isUidBlocked(uid: Int): Boolean {
        if (uid == -1) return false
        return uid in currentBlockedUids()
    }

    @Volatile
    private var cachedProviderPackages: Set<String> = emptySet()
    @Volatile
    private var cachedProviderPackagesAt: Long = 0L
    private val providerCacheTtlMs = 2000L

    private fun currentBlockedPackages(): Set<String> {
        val now = SystemClock.elapsedRealtime()
        val cached = cachedProviderPackages
        if (now - cachedProviderPackagesAt < providerCacheTtlMs) return cached
        val fresh = runCatching { blockedPackagesProvider() }.getOrDefault(cached)
        cachedProviderPackages = fresh
        cachedProviderPackagesAt = now
        return fresh
    }

    private fun currentBlockedUids(): Set<Int> {
        val packages = currentBlockedPackages()
        return synchronized(this) {
            if (packages == cachedBlockedPackages) return@synchronized cachedBlockedUids
            val uids = mutableSetOf<Int>()
            for (pkg in packages) {
                val uid = runCatching {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        packageManager.getApplicationInfo(pkg, android.content.pm.PackageManager.ApplicationInfoFlags.of(0)).uid
                    } else {
                        @Suppress("DEPRECATION")
                        packageManager.getApplicationInfo(pkg, 0).uid
                    }
                }.getOrNull()
                if (uid != null) uids.add(uid)
            }
            cachedBlockedPackages = packages
            cachedBlockedUids = uids
            uids
        }
    }

    private inner class TcpSession(
        val key: FlowKey,
        val version: Int,
        val clientIp: ByteArray,
        val serverIp: ByteArray,
        val clientPort: Int,
        val serverPort: Int,
        initialSeq: Long,
        val uid: Int
    ) {
        private val queue = java.util.concurrent.LinkedBlockingDeque<ByteArray>(8192)
        private val isClosed = AtomicBoolean(false)
        private var sock: Socket? = null
        private val mySeq = AtomicLong((100000..900000).random().toLong())
        private val myAck = AtomicLong((initialSeq + 1) and 0xFFFFFFFFL)
        private val connected = AtomicBoolean(false)
        private val clientClosed = AtomicBoolean(false)
        private val outputShutdown = AtomicBoolean(false)
        private val createdAt = SystemClock.elapsedRealtime()
        private val lastActivity = AtomicLong(SystemClock.elapsedRealtime())
        private val bytesUp = AtomicLong(0)
        private val bytesDown = AtomicLong(0)
        private val peerAck = AtomicLong(0)
        private val targetLabel: String by lazy { InetAddress.getByAddress(serverIp).hostAddress ?: "?" }
        private val state = java.util.concurrent.atomic.AtomicReference(TcpState.SYN_RCVD)
        private val terminalSent = AtomicBoolean(false)

        fun isConnected(): Boolean = connected.get()
        fun isActiveFlow(now: Long): Boolean {
            if (!connected.get()) return lastActivity.get() + 10000 > now
            return lastActivity.get() + TCP_IDLE_MS > now
        }
        private fun sendRstOnce() {
            if (terminalSent.compareAndSet(false, true)) {
                val rst = if (version == 4) {
                    buildTcp4(bytesToInt(serverIp), bytesToInt(clientIp), serverPort, clientPort, null, mySeq.get(), myAck.get(), 0x04)
                } else {
                    buildTcp6(serverIp, clientIp, serverPort, clientPort, null, mySeq.get(), myAck.get(), 0x04)
                }
                enqueueTun(rst, true)
            }
            state.set(TcpState.CLOSING)
            close()
        }
        private fun sendFinOnce() {
            if (terminalSent.compareAndSet(false, true)) {
                val fin = if (version == 4) {
                    buildTcp4(bytesToInt(serverIp), bytesToInt(clientIp), serverPort, clientPort, null, mySeq.get(), myAck.get(), 0x11)
                } else {
                    buildTcp6(serverIp, clientIp, serverPort, clientPort, null, mySeq.get(), myAck.get(), 0x11)
                }
                enqueueTun(fin, true)
                mySeq.set((mySeq.get() + 1) and 0xFFFFFFFFL)
            }
            state.set(TcpState.CLOSING)
            close()
        }

        fun handleFromTun(seq: Long, ack: Long, payload: ByteArray?, flags: Int) {
            if (isClosed.get()) return

            lastActivity.set(SystemClock.elapsedRealtime())
            peerAck.set(ack)

            if ((flags and 0x04) != 0) {
                close()
                return
            }

            if (!connected.get()) {
                if ((flags and 0x01) != 0) {
                    close()
                    return
                }
                if (payload != null && seq == myAck.get()) {
                    if (queue.offer(payload)) {
                        myAck.set((seq + payload.size) and 0xFFFFFFFFL)
                        bytesUp.addAndGet(payload.size.toLong())
                    }
                    sendAck()
                }
                return
            }

            val currentAck = myAck.get()

            if ((flags and 0x01) != 0) {
                if (seq == currentAck) {
                    myAck.set((seq + 1) and 0xFFFFFFFFL)
                    sendAck()
                    clientClosed.set(true)
                } else {
                    sendAck()
                }
                return
            }

            if (payload == null) return

            if (seq == currentAck) {
                if (queue.offer(payload)) {
                    myAck.set((seq + payload.size) and 0xFFFFFFFFL)
                    sendAck()
                }
            } else {
                sendAck()
            }
        }

        private fun sendAck() {
            val packet = if (version == 4) {
                buildTcp4(bytesToInt(serverIp), bytesToInt(clientIp), serverPort, clientPort, null, mySeq.get(), myAck.get(), 0x10)
            } else {
                buildTcp6(serverIp, clientIp, serverPort, clientPort, null, mySeq.get(), myAck.get(), 0x10)
            }
            enqueueTun(packet, true)
        }

        fun run() {
            state.set(TcpState.POLICY)
            try {
                val targetIpStr: String = InetAddress.getByAddress(serverIp).hostAddress ?: ""
                if (!gateReady()) {
                    sendRstOnce()
                    return
                }
                var cachedDomain = DnsMap.get(targetIpStr)
                var decision = routingEngine.resolve(targetIpStr, serverPort, cachedDomain, null, null)
                if (decision.mode == RoutingMode.BLOCK) {
                    cacheBlock(targetIpStr, serverPort, decision.resolvedDomain ?: cachedDomain)
                    LogRepository.i("[Routing] BLOCK domain=${decision.resolvedDomain ?: "unknown"} ip=$targetIpStr protocol=TCP")
                    blockRstCount.incrementAndGet()
                    sendRstOnce()
                    return
                }
                val needSniff = (serverPort == 80 || serverPort == 443) && cachedDomain == null && routingEngine.hasDomainRules()
                var sniffedDomain: String? = null
                var firstPayload: ByteArray? = null
                if (needSniff) {
                    val deadline = SystemClock.elapsedRealtime() + SNI_WAIT_MS
                    while (SystemClock.elapsedRealtime() < deadline) {
                        if (isClosed.get() || !isRunning.get()) return
                        val p = queue.poll(25, TimeUnit.MILLISECONDS) ?: continue
                        firstPayload = p
                        break
                    }
                    if (firstPayload != null) {
                        sniffedDomain = TrafficSniffer.sniffDomain(firstPayload, serverPort)
                        if (sniffedDomain != null) {
                            DnsMap.put(targetIpStr, sniffedDomain)
                            cachedDomain = sniffedDomain
                            decision = routingEngine.resolve(targetIpStr, serverPort, null, if (serverPort == 443) sniffedDomain else null, if (serverPort == 80) sniffedDomain else null)
                            if (decision.mode == RoutingMode.BLOCK) {
                                cacheBlock(targetIpStr, serverPort, decision.resolvedDomain ?: sniffedDomain)
                                LogRepository.i("[Routing] BLOCK domain=${decision.resolvedDomain ?: "unknown"} ip=$targetIpStr protocol=TCP")
                                blockRstCount.incrementAndGet()
                                sendRstOnce()
                                return
                            }
                        }
                    }
                }
                val requestedDirect = decision.mode == RoutingMode.DIRECT
                val directNetwork = if (requestedDirect) underlyingNetwork() else null
                var useDirect = requestedDirect && directNetwork != null && ((version == 4 && supportsIpv4(directNetwork)) || (version == 6 && supportsIpv6(directNetwork)))
                if (decision.matchedRule != null) {
                    LogRepository.i("[Routing] ${decision.mode.name} domain=${decision.resolvedDomain ?: "unknown"} ip=$targetIpStr protocol=TCP")
                }
                if (requestedDirect && !useDirect) {
                    LogRepository.i("[Routing] DIRECT_FALLBACK domain=${decision.resolvedDomain ?: "unknown"} ip=$targetIpStr protocol=TCP reason=no_underlying_route")
                    useDirect = false
                }
                if (useDirect) directFlowCount.incrementAndGet() else tunnelFlowCount.incrementAndGet()
                val synAck = if (version == 4) {
                    buildTcp4(bytesToInt(serverIp), bytesToInt(clientIp), serverPort, clientPort, null, mySeq.get(), myAck.get(), 0x12)
                } else {
                    buildTcp6(serverIp, clientIp, serverPort, clientPort, null, mySeq.get(), myAck.get(), 0x12)
                }
                enqueueTun(synAck, true)
                mySeq.set((mySeq.get() + 1) and 0xFFFFFFFFL)
                state.set(TcpState.CONNECTING)
                val s = Socket()
                sock = s
                s.tcpNoDelay = true
                s.keepAlive = true
                s.receiveBufferSize = 262144
                s.sendBufferSize = 262144
                val ins: InputStream
                val out: OutputStream
                if (useDirect && directNetwork != null) {
                    val network = directNetwork
                    network.bindSocket(s)
                    try {
                        s.connect(InetSocketAddress(targetIpStr, serverPort), connectTimeoutMs())
                    } catch (_: Exception) {
                        sendRstOnce()
                        return
                    }
                    ins = s.getInputStream()
                    out = BufferedOutputStream(s.getOutputStream(), 131072)
                    val directNetworkType = networkLabel(network)
                    LogRepository.i("[Routing] DIRECT_CONNECTED domain=${decision.resolvedDomain ?: "unknown"} ip=$targetIpStr via=$directNetworkType local=${s.localAddress.hostAddress}")
                    DirectRouteVerifier.verify(decision.resolvedDomain ?: targetIpStr, network, directNetworkType)
                } else {
                    if (!vpnService.protect(s)) {
                        LogRepository.w("[TunBridge] protect failed for $targetIpStr:$serverPort")
                        sendRstOnce()
                        return
                    }
                    try {
                        s.connect(InetSocketAddress(socksHost, socksPort), connectTimeoutMs())
                    } catch (e: Exception) {
                        val gate = SocksGate.readiness.value
                        LogRepository.w("[TunBridge] upstream connect failed target=$targetIpStr:$serverPort gate=$gate err=${e.message}")
                        sendRstOnce()
                        return
                    }
                    ins = s.getInputStream()
                    out = BufferedOutputStream(s.getOutputStream(), 131072)
                    if (!socksHandshake(ins, out)) {
                        LogRepository.w("[TunBridge] SOCKS5 handshake failed for target=$targetIpStr:$serverPort mtu=$mtu gate=${SocksGate.readiness.value}")
                        sendRstOnce()
                        return
                    }
                    out.write(socksRequest(1, sniffedDomain ?: cachedDomain, serverIp, serverPort))
                    out.flush()
                    if (readSocksReply(ins) == null) {
                        LogRepository.w("[TunBridge] SOCKS5 CONNECT reply failed for target=$targetIpStr:$serverPort mtu=$mtu gate=${SocksGate.readiness.value}")
                        sendRstOnce()
                        return
                    }
                }
                connected.set(true)
                state.set(TcpState.ESTABLISHED)
                lastActivity.set(SystemClock.elapsedRealtime())
                if (isClosed.get()) return
                try {
                    bridgeScope.launch { readFromSocks(ins) }
                } catch (_: Exception) {
                    sendRstOnce()
                    return
                }
                if (firstPayload != null) {
                    val late = TrafficSniffer.sniffDomain(firstPayload, serverPort)
                    val eff = late ?: sniffedDomain
                    if (eff != null && eff != cachedDomain) {
                        val rd = routingEngine.resolve(targetIpStr, serverPort, null, if (serverPort == 443) eff else null, if (serverPort == 80) eff else null)
                        if (rd.mode == RoutingMode.BLOCK) {
                            cacheBlock(targetIpStr, serverPort, rd.resolvedDomain ?: eff)
                            blockRstCount.incrementAndGet()
                            sendRstOnce()
                            return
                        }
                    }
                    try {
                        out.write(firstPayload)
                        out.flush()
                        bytesUp.addAndGet(firstPayload.size.toLong())
                        lastActivity.set(SystemClock.elapsedRealtime())
                    } catch (_: Exception) {
                        sendFinOnce()
                        return
                    }
                    firstPayload = null
                }
                var sniffDone = sniffedDomain != null || !needSniff
                while (!isClosed.get() && isRunning.get()) {
                    val data = queue.poll(2, TimeUnit.SECONDS)
                    if (data == null) {
                        if (clientClosed.get() && queue.isEmpty() && outputShutdown.compareAndSet(false, true)) {
                            runCatching { sock?.shutdownOutput() }
                        }
                        if (SystemClock.elapsedRealtime() - lastActivity.get() > TCP_IDLE_MS) {
                            sendFinOnce()
                            break
                        }
                        continue
                    }
                    if (!sniffDone && (serverPort == 80 || serverPort == 443)) {
                        val late = TrafficSniffer.sniffDomain(data, serverPort)
                        sniffDone = true
                        if (late != null) {
                            DnsMap.put(targetIpStr, late)
                            val rd = routingEngine.resolve(targetIpStr, serverPort, null, if (serverPort == 443) late else null, if (serverPort == 80) late else null)
                            if (rd.mode == RoutingMode.BLOCK) {
                                cacheBlock(targetIpStr, serverPort, rd.resolvedDomain ?: late)
                                blockRstCount.incrementAndGet()
                                sendRstOnce()
                                return
                            }
                        }
                    }
                    try {
                        out.write(data)
                    } catch (_: Exception) {
                        sendFinOnce()
                        break
                    }
                    var count = 0
                    var drainBytes = data.size
                    while (count < 64) {
                        val next = queue.poll() ?: break
                        try {
                            out.write(next)
                        } catch (_: Exception) {
                            sendFinOnce()
                            return
                        }
                        drainBytes += next.size
                        count++
                    }
                    try {
                        out.flush()
                    } catch (_: Exception) {
                        sendFinOnce()
                        break
                    }
                    bytesUp.addAndGet(drainBytes.toLong())
                    lastActivity.set(SystemClock.elapsedRealtime())
                    if (clientClosed.get() && queue.isEmpty() && outputShutdown.compareAndSet(false, true)) {
                        runCatching { sock?.shutdownOutput() }
                    }
                }
            } catch (exception: Exception) {
                if (isRunning.get() && !isClosed.get()) {
                    LogRepository.w("[Routing] TCP session failed: ${exception.localizedMessage}")
                }
            } finally {
                close()
            }
        }

        private fun readFromSocks(ins: InputStream) {
            try {
                val buffer = ByteArray(131072)
                val maxPayload = if (version == 4) (mtu - 40).coerceAtLeast(20) else (mtu - 60).coerceAtLeast(20)

                while (!isClosed.get() && isRunning.get()) {
                    val n = ins.read(buffer)

                    if (n <= 0) {
                        sendFinOnce()
                        break
                    }

                    lastActivity.set(SystemClock.elapsedRealtime())
                    bytesDown.addAndGet(n.toLong())

                    var offset = 0
                    while (offset < n) {
                        val chunkLen = minOf(maxPayload, n - offset)
                        val chunk = buffer.copyOfRange(offset, offset + chunkLen)

                        val packet = if (version == 4) {
                            buildTcp4(bytesToInt(serverIp), bytesToInt(clientIp), serverPort, clientPort, chunk, mySeq.get(), myAck.get(), 0x18)
                        } else {
                            buildTcp6(serverIp, clientIp, serverPort, clientPort, chunk, mySeq.get(), myAck.get(), 0x18)
                        }

                        enqueueTun(packet)
                        mySeq.set((mySeq.get() + chunkLen) and 0xFFFFFFFFL)
                        offset += chunkLen
                    }
                }
            } catch (_: Exception) {
            } finally {
                close()
            }
        }

        fun close() {
            if (isClosed.getAndSet(true)) return
            state.set(TcpState.CLOSING)
            runCatching { sock?.close() }
            tcpSessions.remove(key, this)
            uidCache.remove(key)
        }
        fun forceClose() {
            if (isClosed.getAndSet(true)) return
            state.set(TcpState.CLOSING)
            runCatching { sock?.close() }
            uidCache.remove(key)
        }
    }

    private inner class UdpSession(
        val key: FlowKey,
        val version: Int,
        val clientIp: ByteArray,
        val serverIp: ByteArray,
        val clientPort: Int,
        val serverPort: Int,
        val uid: Int
    ) {
        private val payloadQueue = LinkedBlockingQueue<ByteArray>(2048)
        private val isClosed = AtomicBoolean(false)
        private var ctrlSock: Socket? = null
        private var udpSock: DatagramSocket? = null
        private val lastActivity = AtomicLong(SystemClock.elapsedRealtime())

        fun queue(data: ByteArray): Boolean {
            if (isClosed.get()) return false
            val ok = payloadQueue.offer(data)
            if (ok) lastActivity.set(SystemClock.elapsedRealtime())
            return ok
        }
        fun isActiveFlow(now: Long): Boolean {
            val idle = if (isVoipPort(serverPort)) UDP_IDLE_VOIP else UDP_IDLE_SHORT
            return lastActivity.get() + idle > now
        }

        fun run() {
            try {
                val targetIpStr: String = InetAddress.getByAddress(serverIp).hostAddress ?: ""
                val targetDomain = DnsMap.get(targetIpStr)
                
                val decision = routingEngine.resolve(targetIpStr, serverPort, targetDomain, null, null)
                val requestedDirect = decision.mode == RoutingMode.DIRECT
                val directNetwork = if (requestedDirect) underlyingNetwork() else null
                var isDirect = requestedDirect && directNetwork != null && (
                    (version == 4 && supportsIpv4(directNetwork)) ||
                    (version == 6 && supportsIpv6(directNetwork))
                )

                if (serverPort == 443 && targetDomain == null && routingEngine.hasDomainRules()) {
                    LogRepository.d("[Routing] QUIC cold DnsMap miss ip=$targetIpStr protocol=UDP; fallback TUNNEL")
                }

                if (decision.matchedRule != null) {
                    LogRepository.i("[Routing] ${decision.mode.name} domain=${decision.resolvedDomain ?: "unknown"} ip=$targetIpStr protocol=UDP")
                }

                if (requestedDirect && !isDirect) {
                    LogRepository.i("[Routing] DIRECT_FALLBACK domain=${decision.resolvedDomain ?: "unknown"} ip=$targetIpStr protocol=UDP reason=no_underlying_route")
                    isDirect = false
                }
                
                if (decision.mode == RoutingMode.BLOCK) {
                    cacheBlock(targetIpStr, serverPort, decision.resolvedDomain ?: targetDomain)
                    blockRstCount.incrementAndGet()
                    close()
                    return
                }
                if (!gateReady()) {
                    fastGateDrop.incrementAndGet()
                    close()
                    return
                }
                val relayHost: InetAddress
                val relayPort: Int
                val header: ByteArray
                var sharedRelay: InetSocketAddress? = null
                if (isDirect) {
                    relayHost = InetAddress.getByName(targetIpStr)
                    relayPort = serverPort
                    header = ByteArray(0)
                } else {
                    sharedRelay = associatePool.relayFor()
                    if (sharedRelay != null) {
                        relayHost = sharedRelay.address
                        relayPort = sharedRelay.port
                        header = socksUdpHeader(targetDomain, serverIp, serverPort)
                    } else {
                        val ctrl = Socket()
                        ctrlSock = ctrl
                        if (!vpnService.protect(ctrl)) {
                            LogRepository.w("[TunBridge] UDP protect ctrl failed for $targetIpStr:$serverPort")
                        }
                        ctrl.tcpNoDelay = true
                        try {
                            ctrl.connect(InetSocketAddress(socksHost, socksPort), connectTimeoutMs())
                        } catch (e: Exception) {
                            LogRepository.w("[TunBridge] UDP upstream connect failed target=$targetIpStr:$serverPort gate=${SocksGate.readiness.value} err=${e.message}")
                            close()
                            return
                        }
                    val ins = ctrl.getInputStream()
                    val out = ctrl.getOutputStream()
                    if (!socksHandshake(ins, out)) {
                        LogRepository.w("[TunBridge] UDP: SOCKS5 handshake failed for target=$targetIpStr:$serverPort mtu=$mtu gate=${SocksGate.readiness.value}")
                        close()
                        return
                    }
                    val associateAddress = if (version == 4) ByteArray(4) else ByteArray(16)
                    out.write(socksRequest(3, null, associateAddress, 0))
                    out.flush()
                    val relay = readSocksReply(ins) ?: run {
                        LogRepository.w("[TunBridge] UDP: SOCKS5 ASSOCIATE reply failed for target=$targetIpStr:$serverPort mtu=$mtu gate=${SocksGate.readiness.value}")
                        close()
                        return
                    }
                    relayHost = if (relay.address.isAnyLocalAddress) InetAddress.getByName(socksHost) else relay.address
                    relayPort = relay.port
                    header = socksUdpHeader(targetDomain, serverIp, serverPort)
                    }
                }

                val relaySocket = DatagramSocket()
                udpSock = relaySocket
                if (isDirect && directNetwork != null) {
                    val network = directNetwork
                    network.bindSocket(relaySocket)
                    val directNetworkType = networkLabel(network)
                    LogRepository.i("[Routing] DIRECT_UDP_BOUND domain=${decision.resolvedDomain ?: "unknown"} ip=$targetIpStr via=$directNetworkType")
                    DirectRouteVerifier.verify(decision.resolvedDomain ?: targetIpStr, network, directNetworkType)
                } else {
                    if (!vpnService.protect(relaySocket)) {
                        LogRepository.w("[TunBridge] UDP protect relay failed for $targetIpStr:$serverPort")
                    }
                }
                relaySocket.soTimeout = 10000

                try {
                    bridgeScope.launch { receiveFromNetwork(relaySocket, isDirect) }
                } catch (_: Exception) {
                    close()
                    return
                }

                val relayAddress = InetSocketAddress(relayHost, relayPort)
                val idleTimeoutMs = if (isVoipPort(serverPort)) UDP_IDLE_VOIP else UDP_IDLE_SHORT

                while (!isClosed.get() && isRunning.get()) {
                    val payload = payloadQueue.poll(2, TimeUnit.SECONDS)

                    if (payload == null) {
                        if (SystemClock.elapsedRealtime() - lastActivity.get() > idleTimeoutMs) {
                            close()
                            break
                        }
                        continue
                    }

                    val full = if (isDirect) {
                        payload
                    } else {
                        val f = ByteArray(header.size + payload.size)
                        System.arraycopy(header, 0, f, 0, header.size)
                        System.arraycopy(payload, 0, f, header.size, payload.size)
                        f
                    }

                    relaySocket.send(DatagramPacket(full, full.size, relayAddress))
                    lastActivity.set(SystemClock.elapsedRealtime())
                }
            } catch (exception: Exception) {
                if (isRunning.get() && !isClosed.get()) {
                    LogRepository.w("[Routing] UDP session failed: ${exception.localizedMessage}")
                }
            } finally {
                close()
            }
        }

        private fun receiveFromNetwork(sock: DatagramSocket, direct: Boolean) {
            try {
                val buf = ByteArray(65535)
                val maxPayload = if (version == 4) (mtu - 28).coerceAtLeast(8) else (mtu - 48).coerceAtLeast(8)

                while (!isClosed.get() && isRunning.get()) {
                    try {
                        val packet = DatagramPacket(buf, buf.size)
                        sock.receive(packet)
                        lastActivity.set(SystemClock.elapsedRealtime())

                        val source: SocksAddress
                        val payload: ByteArray
                        if (direct) {
                            source = SocksAddress(packet.address, packet.port)
                            payload = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                        } else {
                            val parsed = parseSocksUdp(packet.data, packet.length) ?: continue
                            source = parsed.first
                            payload = parsed.second
                        }

                        if (payload.size > 8192) continue
                        if (payload.size > maxPayload) {
                            LogRepository.w("[TunBridge] UDP rx payload ${payload.size} > MTU-derived $maxPayload for $serverPort; forwarding anyway")
                        }
                        if (source.port == 53) sniffDnsResponse(payload)
                        val srcBytes = source.address.address

                        if (version == 4 && srcBytes.size == 4) {
                            enqueueTun(buildUdp4(bytesToInt(srcBytes), bytesToInt(clientIp), source.port, clientPort, payload))
                        } else if (version == 6 && srcBytes.size == 16) {
                            enqueueTun(buildUdp6(srcBytes, clientIp, source.port, clientPort, payload))
                        }
                    } catch (_: SocketTimeoutException) {
                        val t = if (isVoipPort(serverPort)) UDP_IDLE_VOIP else UDP_IDLE_SHORT
                        if (SystemClock.elapsedRealtime() - lastActivity.get() > t) break
                    } catch (_: Exception) {
                        break
                    }
                }
            } finally {
                close()
            }
        }

        fun close() {
            if (isClosed.getAndSet(true)) return
            val shared = ctrlSock == null
            if (!shared) runCatching { ctrlSock?.close() }
            runCatching { udpSock?.close() }
            udpSessions.remove(key, this)
            uidCache.remove(key)
        }
        fun forceClose() {
            if (isClosed.getAndSet(true)) return
            runCatching { ctrlSock?.close() }
            runCatching { udpSock?.close() }
            uidCache.remove(key)
        }
    }

    private fun socksHandshake(ins: InputStream, out: OutputStream): Boolean {
        out.write(byteArrayOf(5, 1, 0))
        out.flush()
        val response = ByteArray(2)
        if (!readExact(ins, response)) return false
        return response[0] == 5.toByte() && response[1] == 0.toByte()
    }

    private fun socksRequest(command: Int, domain: String?, address: ByteArray, port: Int): ByteArray {
        if (domain != null) {
            val db = domain.toByteArray()
            val req = ByteArray(7 + db.size)
            req[0] = 5
            req[1] = command.toByte()
            req[2] = 0
            req[3] = 3
            req[4] = db.size.toByte()
            System.arraycopy(db, 0, req, 5, db.size)
            req[5 + db.size] = (port shr 8).toByte()
            req[6 + db.size] = (port and 0xFF).toByte()
            return req
        }
        val req = ByteArray(6 + address.size)
        req[0] = 5
        req[1] = command.toByte()
        req[2] = 0
        req[3] = if (address.size == 4) 1 else 4
        System.arraycopy(address, 0, req, 4, address.size)
        req[4 + address.size] = (port shr 8).toByte()
        req[5 + address.size] = (port and 0xFF).toByte()
        return req
    }

    private fun readSocksReply(ins: InputStream): SocksAddress? {
        val header = ByteArray(4)
        if (!readExact(ins, header)) return null
        if (header[0] != 5.toByte() || header[1] != 0.toByte()) return null

        when (header[3].toInt() and 0xFF) {
            1 -> {
                val b = ByteArray(6)
                if (!readExact(ins, b)) return null
                return SocksAddress(InetAddress.getByAddress(b.copyOfRange(0, 4)), getShort(b, 4))
            }
            4 -> {
                val b = ByteArray(18)
                if (!readExact(ins, b)) return null
                return SocksAddress(InetAddress.getByAddress(b.copyOfRange(0, 16)), getShort(b, 16))
            }
            3 -> {
                val lenByte = ByteArray(1)
                if (!readExact(ins, lenByte)) return null
                val domainLength = lenByte[0].toInt() and 0xFF
                val domain = ByteArray(domainLength)
                if (!readExact(ins, domain)) return null
                val portBytes = ByteArray(2)
                if (!readExact(ins, portBytes)) return null
                val address = runCatching { InetAddress.getByName(String(domain)) }.getOrNull() ?: return null
                return SocksAddress(address, getShort(portBytes, 0))
            }
            else -> return null
        }
    }

    private fun parseSocksUdp(data: ByteArray, len: Int): Pair<SocksAddress, ByteArray>? {
        if (len < 4) return null

        val atyp = data[3].toInt() and 0xFF
        val offset: Int
        val address: InetAddress
        val port: Int

        when (atyp) {
            1 -> {
                if (len < 10) return null
                address = InetAddress.getByAddress(data.copyOfRange(4, 8))
                port = getShort(data, 8)
                offset = 10
            }
            4 -> {
                if (len < 22) return null
                address = InetAddress.getByAddress(data.copyOfRange(4, 20))
                port = getShort(data, 20)
                offset = 22
            }
            3 -> {
                if (len < 5) return null
                val domainLength = data[4].toInt() and 0xFF
                if (len < 5 + domainLength + 2) return null
                val domain = data.copyOfRange(5, 5 + domainLength)
                address = runCatching { InetAddress.getByName(String(domain)) }.getOrNull() ?: return null
                port = getShort(data, 5 + domainLength)
                offset = 5 + domainLength + 2
            }
            else -> return null
        }

        if (len < offset) return null
        return Pair(SocksAddress(address, port), data.copyOfRange(offset, len))
    }

    private fun socksUdpHeader(domain: String?, address: ByteArray, port: Int): ByteArray {
        if (domain != null) {
            val db = domain.toByteArray()
            val h = ByteArray(7 + db.size)
            h[0] = 0
            h[1] = 0
            h[2] = 0
            h[3] = 3
            h[4] = db.size.toByte()
            System.arraycopy(db, 0, h, 5, db.size)
            h[5 + db.size] = (port shr 8).toByte()
            h[6 + db.size] = (port and 0xFF).toByte()
            return h
        }
        val header = ByteArray(6 + address.size)
        header[0] = 0
        header[1] = 0
        header[2] = 0
        header[3] = if (address.size == 4) 1 else 4
        System.arraycopy(address, 0, header, 4, address.size)
        header[4 + address.size] = (port shr 8).toByte()
        header[5 + address.size] = (port and 0xFF).toByte()
        return header
    }

    private fun readExact(ins: InputStream, b: ByteArray): Boolean {
        var o = 0
        while (o < b.size) {
            val c = ins.read(b, o, b.size - o)
            if (c < 0) return false
            o += c
        }
        return true
    }

    private fun sniffDnsResponse(data: ByteArray) {
        if (data.size < 12) return
        try {
            val flags = getShort(data, 2)
            if (flags and 0x8000 == 0) return 
            
            val qCount = getShort(data, 4)
            val aCount = getShort(data, 6)
            if (qCount == 0 || aCount == 0) return
            
            var pos = 12
            repeat(qCount) {
                while (pos < data.size) {
                    val l = data[pos].toInt() and 0xFF
                    if (l == 0) { pos++; break }
                    if (l >= 0xC0) { pos += 2; break }
                    pos += l + 1
                }
                pos += 4
            }
            
            val domain = extractDomainName(data, data.size) ?: return
            
            repeat(aCount) {
                if (pos + 12 > data.size) return@repeat
                
                if ((data[pos].toInt() and 0xFF) >= 0xC0) {
                    pos += 2
                } else {
                    while (pos < data.size) {
                        val l = data[pos].toInt() and 0xFF
                        if (l == 0) { pos++; break }
                        pos += l + 1
                    }
                }
                
                val type = getShort(data, pos)
                val rdLen = getShort(data, pos + 8)
                pos += 10
                
                if (type == 1 && rdLen == 4 && pos + 4 <= data.size) {
                    val ip = "${data[pos].toInt() and 0xFF}.${data[pos+1].toInt() and 0xFF}.${data[pos+2].toInt() and 0xFF}.${data[pos+3].toInt() and 0xFF}"
                    DnsMap.put(ip, domain)
                } else if (type == 28 && rdLen == 16 && pos + 16 <= data.size) {
                    val ip = InetAddress.getByAddress(data.copyOfRange(pos, pos + 16)).hostAddress ?: ""
                    DnsMap.put(ip, domain)
                }
                pos += rdLen
            }
        } catch (_: Exception) {}
    }

    private fun extractDomainName(data: ByteArray, length: Int): String? {
        if (length < 12) return null
        return try {
            val sb = StringBuilder()
            var pos = 12
            while (pos < length) {
                val l = data[pos].toInt() and 0xFF
                if (l == 0) break
                if (sb.isNotEmpty()) sb.append(".")
                if (pos + 1 + l > length) return null
                sb.append(String(data, pos + 1, l))
                pos += l + 1
            }
            sb.toString().lowercase()
        } catch (_: Exception) {
            null
        }
    }


    private fun buildDnsNXResponse(requestData: ByteArray): ByteArray? {
        if (requestData.size < 12) return null
        return try {
            val questionEnd = findDnsQuestionEnd(requestData)
            val resp = requestData.copyOfRange(0, questionEnd)
            resp[2] = (resp[2].toInt() or 0x80).toByte()
            resp[3] = ((resp[3].toInt() and 0x70) or 0x80 or 0x03).toByte()
            for (i in 6..11) resp[i] = 0
            resp
        } catch (_: Exception) {
            null
        }
    }

    private fun findDnsQuestionEnd(data: ByteArray): Int {
        var i = 12
        while (i < data.size) {
            val len = data[i].toInt() and 0xFF
            if (len == 0) {
                i++
                break
            }
            if (len >= 0xC0) {
                i += 2
                break
            }
            i += len + 1
        }
        return minOf(data.size, i + 4)
    }

    private fun buildTcp4(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        data: ByteArray?,
        seq: Long,
        ack: Long,
        flags: Int
    ): ByteArray {
        val isSynAck = flags == 0x12
        val optLen = if (isSynAck) 4 else 0
        val dSize = data?.size ?: 0
        val total = 40 + optLen + dSize
        val p = ByteArray(total)

        p[0] = 0x45
        p[2] = (total shr 8).toByte()
        p[3] = (total and 0xFF).toByte()
        p[8] = 64
        p[9] = 6

        setInt(p, 12, srcIp)
        setInt(p, 16, dstIp)

        val ipCk = calculateChecksum(p)
        p[10] = (ipCk shr 8).toByte()
        p[11] = (ipCk and 0xFF).toByte()

        setShort(p, 20, srcPort)
        setShort(p, 22, dstPort)
        setLong(p, 24, seq)
        setLong(p, 28, ack)

        p[32] = ((5 + optLen / 4) shl 4).toByte()
        p[33] = flags.toByte()
        p[34] = 0xFF.toByte()
        p[35] = 0xFF.toByte()

        if (isSynAck) {
            val mss = (mtu - 40).coerceAtLeast(536)
            p[40] = 2
            p[41] = 4
            p[42] = (mss shr 8).toByte()
            p[43] = (mss and 0xFF).toByte()
        }

        data?.let { System.arraycopy(it, 0, p, 40 + optLen, it.size) }

        val tcpSegment = p.copyOfRange(20, total)
        var tcpCk = calculateTransportChecksum4(srcIp, dstIp, tcpSegment, 6)
        if (tcpCk == 0) tcpCk = 0xFFFF

        p[36] = (tcpCk shr 8).toByte()
        p[37] = (tcpCk and 0xFF).toByte()

        return p
    }

    private fun buildTcp6(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        data: ByteArray?,
        seq: Long,
        ack: Long,
        flags: Int
    ): ByteArray {
        val isSynAck = flags == 0x12
        val optLen = if (isSynAck) 4 else 0
        val dSize = data?.size ?: 0
        val tcpLen = 20 + optLen + dSize
        val total = 40 + tcpLen
        val p = ByteArray(total)

        p[0] = 0x60
        p[4] = (tcpLen shr 8).toByte()
        p[5] = (tcpLen and 0xFF).toByte()
        p[6] = 6
        p[7] = 64

        System.arraycopy(srcIp, 0, p, 8, 16)
        System.arraycopy(dstIp, 0, p, 24, 16)

        setShort(p, 40, srcPort)
        setShort(p, 42, dstPort)
        setLong(p, 44, seq)
        setLong(p, 48, ack)

        p[52] = ((5 + optLen / 4) shl 4).toByte()
        p[53] = flags.toByte()
        p[54] = 0xFF.toByte()
        p[55] = 0xFF.toByte()

        if (isSynAck) {
            val mss = (mtu - 60).coerceAtLeast(536)
            p[60] = 2
            p[61] = 4
            p[62] = (mss shr 8).toByte()
            p[63] = (mss and 0xFF).toByte()
        }

        data?.let { System.arraycopy(it, 0, p, 60 + optLen, it.size) }

        val tcpSegment = p.copyOfRange(40, total)
        var tcpCk = calculateTransportChecksum6(srcIp, dstIp, tcpSegment, 6)
        if (tcpCk == 0) tcpCk = 0xFFFF

        p[56] = (tcpCk shr 8).toByte()
        p[57] = (tcpCk and 0xFF).toByte()

        return p
    }

    private fun buildUdp4(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        data: ByteArray
    ): ByteArray {
        val udpLen = 8 + data.size
        val total = 20 + udpLen
        val p = ByteArray(total)

        p[0] = 0x45
        p[2] = (total shr 8).toByte()
        p[3] = (total and 0xFF).toByte()
        p[8] = 64
        p[9] = 17

        setInt(p, 12, srcIp)
        setInt(p, 16, dstIp)

        val ipCk = calculateChecksum(p)
        p[10] = (ipCk shr 8).toByte()
        p[11] = (ipCk and 0xFF).toByte()

        setShort(p, 20, srcPort)
        setShort(p, 22, dstPort)
        setShort(p, 24, udpLen)

        System.arraycopy(data, 0, p, 28, data.size)

        val udpSegment = p.copyOfRange(20, total)
        var udpCk = calculateTransportChecksum4(srcIp, dstIp, udpSegment, 17)
        if (udpCk == 0) udpCk = 0xFFFF

        p[26] = (udpCk shr 8).toByte()
        p[27] = (udpCk and 0xFF).toByte()

        return p
    }

    private fun buildUdp6(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        data: ByteArray
    ): ByteArray {
        val udpLen = 8 + data.size
        val total = 40 + udpLen
        val p = ByteArray(total)

        p[0] = 0x60
        p[4] = (udpLen shr 8).toByte()
        p[5] = (udpLen and 0xFF).toByte()
        p[6] = 17
        p[7] = 64

        System.arraycopy(srcIp, 0, p, 8, 16)
        System.arraycopy(dstIp, 0, p, 24, 16)

        setShort(p, 40, srcPort)
        setShort(p, 42, dstPort)
        setShort(p, 44, udpLen)

        System.arraycopy(data, 0, p, 48, data.size)

        val udpSegment = p.copyOfRange(40, total)
        var udpCk = calculateTransportChecksum6(srcIp, dstIp, udpSegment, 17)
        if (udpCk == 0) udpCk = 0xFFFF

        p[46] = (udpCk shr 8).toByte()
        p[47] = (udpCk and 0xFF).toByte()

        return p
    }

    private fun calculateChecksum(b: ByteArray): Int {
        return foldChecksum(sumBytes(b, 20, 0L))
    }

    private fun calculateTransportChecksum4(srcIp: Int, dstIp: Int, segment: ByteArray, protocol: Int): Int {
        var sum = 0L
        sum += ((srcIp ushr 16) and 0xFFFF).toLong()
        sum += (srcIp and 0xFFFF).toLong()
        sum += ((dstIp ushr 16) and 0xFFFF).toLong()
        sum += (dstIp and 0xFFFF).toLong()
        sum += protocol.toLong()
        sum += segment.size.toLong()
        sum = sumBytes(segment, segment.size, sum)
        return foldChecksum(sum)
    }

    private fun calculateTransportChecksum6(srcIp: ByteArray, dstIp: ByteArray, segment: ByteArray, protocol: Int): Int {
        var sum = 0L
        sum = sumBytes(srcIp, 16, sum)
        sum = sumBytes(dstIp, 16, sum)
        sum += segment.size.toLong()
        sum += protocol.toLong()
        sum = sumBytes(segment, segment.size, sum)
        return foldChecksum(sum)
    }

    private fun sumBytes(b: ByteArray, end: Int, initial: Long): Long {
        var sum = initial
        var i = 0

        while (i < end - 1) {
            sum += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
            i += 2
        }

        if (end % 2 != 0) {
            sum += (b[end - 1].toInt() and 0xFF) shl 8
        }

        return sum
    }

    private fun foldChecksum(sum: Long): Int {
        var s = sum
        while ((s shr 16) > 0) {
            s = (s and 0xFFFF) + (s shr 16)
        }
        return (s.inv() and 0xFFFF).toInt()
    }

    private fun getInt(b: ByteArray, o: Int): Int {
        return ((b[o].toInt() and 0xFF) shl 24) or
                ((b[o + 1].toInt() and 0xFF) shl 16) or
                ((b[o + 2].toInt() and 0xFF) shl 8) or
                (b[o + 3].toInt() and 0xFF)
    }

    private fun setInt(b: ByteArray, o: Int, v: Int) {
        b[o] = (v shr 24).toByte()
        b[o + 1] = (v shr 16).toByte()
        b[o + 2] = (v shr 8).toByte()
        b[o + 3] = (v and 0xFF).toByte()
    }

    private fun getShort(p: ByteArray, o: Int): Int {
        return ((p[o].toInt() and 0xFF) shl 8) or (p[o + 1].toInt() and 0xFF)
    }

    private fun setShort(b: ByteArray, o: Int, v: Int) {
        b[o] = (v shr 8).toByte()
        b[o + 1] = (v and 0xFF).toByte()
    }

    private fun getLong(p: ByteArray, o: Int): Long {
        return ((p[o].toLong() and 0xFF) shl 24) or
                ((p[o + 1].toLong() and 0xFF) shl 16) or
                ((p[o + 2].toLong() and 0xFF) shl 8) or
                (p[o + 3].toLong() and 0xFF)
    }

    private fun setLong(b: ByteArray, o: Int, v: Long) {
        b[o] = (v shr 24).toByte()
        b[o + 1] = (v shr 16).toByte()
        b[o + 2] = (v shr 8).toByte()
        b[o + 3] = (v and 0xFF).toByte()
    }

    private fun intToBytes(v: Int): ByteArray {
        return byteArrayOf(
            (v shr 24).toByte(),
            (v shr 16).toByte(),
            (v shr 8).toByte(),
            (v and 0xFF).toByte()
        )
    }

    private fun bytesToInt(b: ByteArray): Int {
        return ((b[0].toInt() and 0xFF) shl 24) or
                ((b[1].toInt() and 0xFF) shl 16) or
                ((b[2].toInt() and 0xFF) shl 8) or
                (b[3].toInt() and 0xFF)
    }
}
