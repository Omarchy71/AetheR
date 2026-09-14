package io.github.immaghzbad.aetherst.shared.data

import io.github.immaghzbad.aetherst.shared.core.NetworkClient
import io.github.immaghzbad.aetherst.shared.model.IpInfoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Request
import kotlinx.serialization.json.*
import java.net.InetSocketAddress
import java.net.Proxy
import kotlin.time.Duration.Companion.milliseconds

object IpInfoRepository {
    private val _ipInfo = MutableStateFlow(IpInfo())
    val ipInfo: StateFlow<IpInfo> = _ipInfo.asStateFlow()

    private val json = Json { ignoreUnknownKeys = true }
    private val mutex = kotlinx.coroutines.sync.Mutex()

    data class ExitCountry(val ip: String, val countryCode: String, val source: String)

    private val geoProviders = setOf(
        IpInfoProvider.IPSB,
        IpInfoProvider.IPWHOIS,
        IpInfoProvider.FREEIPAPI,
        IpInfoProvider.GEOJS,
        IpInfoProvider.REALLYFREE,
        IpInfoProvider.GEOIPLOOKUP,
        IpInfoProvider.FREE_FREEIPAPI,
        IpInfoProvider.IFCONFIG,
        IpInfoProvider.IPINFO
    )

    private fun directSources(): List<Pair<IpInfoProvider, () -> IpInfo?>> = listOf(
        IpInfoProvider.IPSB to ::tryDirectIpSb,
        IpInfoProvider.IPWHOIS to ::tryDirectIpWhoIs,
        IpInfoProvider.FREEIPAPI to ::tryDirectFreeIpApi,
        IpInfoProvider.GEOJS to ::tryDirectGeojs,
        IpInfoProvider.REALLYFREE to ::tryDirectReallyFree,
        IpInfoProvider.GEOIPLOOKUP to ::tryDirectGeoIpLookup,
        IpInfoProvider.FREE_FREEIPAPI to ::tryDirectFreeFreeIpApi,
        IpInfoProvider.IPIFY to ::tryDirectIpify,
        IpInfoProvider.IFCONFIG to ::tryDirectIfconfig,
        IpInfoProvider.IPINFO to ::tryDirectIpinfoIo
    )

    private fun proxySources(socksHost: String, socksPort: Int): List<Pair<IpInfoProvider, () -> IpInfo?>> = listOf(
        IpInfoProvider.IPSB to { tryViaProxyIpSb(socksHost, socksPort) },
        IpInfoProvider.IPWHOIS to { tryViaProxyIpWhoIs(socksHost, socksPort) },
        IpInfoProvider.FREEIPAPI to { tryViaProxyFreeIpApi(socksHost, socksPort) },
        IpInfoProvider.GEOJS to { tryViaProxyGeojs(socksHost, socksPort) },
        IpInfoProvider.REALLYFREE to { tryViaProxyReallyFree(socksHost, socksPort) },
        IpInfoProvider.GEOIPLOOKUP to { tryViaProxyGeoIpLookup(socksHost, socksPort) },
        IpInfoProvider.FREE_FREEIPAPI to { tryViaProxyFreeFreeIpApi(socksHost, socksPort) },
        IpInfoProvider.IPIFY to { tryViaProxyIpify(socksHost, socksPort) },
        IpInfoProvider.IFCONFIG to { tryViaProxyIfconfig(socksHost, socksPort) },
        IpInfoProvider.IPINFO to { tryViaProxyIpinfoIo(socksHost, socksPort) },
        IpInfoProvider.AMAZON to { tryViaProxyAmazon(socksHost, socksPort) }
    )

    suspend fun fetchExitCountry(socksHost: String = "127.0.0.1", socksPort: Int = 1819, useProxy: Boolean = true): ExitCountry? = coroutineScope {
        val base = if (useProxy) proxySources(socksHost, socksPort) else directSources()
        val ordered = base.filter { geoProviders.contains(it.first) }.shuffled()
        if (ordered.isEmpty()) return@coroutineScope null
        withTimeoutOrNull(18000) {
            val sources = ordered.map { pair -> async { pair.first to pair.second() } }
            for (future in sources) {
                val named = try {
                    future.await()
                } catch (_: Throwable) {
                    continue
                }
                val result = named.second
                val code = result?.countryCode?.trim()?.uppercase() ?: ""
                val ip = result?.ip?.trim() ?: ""
                if (ip.isNotEmpty() && code.isNotEmpty()) {
                    sources.forEach { it.cancel() }
                    LogRepository.i("Exit country via ${named.first.rawValue}: $ip ($code)", "IpWhois")
                    return@withTimeoutOrNull ExitCountry(ip, code, named.first.rawValue)
                }
            }
            null
        }
    }

    suspend fun fetchIpInfo(socksHost: String = "127.0.0.1", socksPort: Int = 1819, useProxy: Boolean = true, provider: IpInfoProvider = IpInfoProvider.AUTO) {
        mutex.lock()
        try {
            _ipInfo.value = _ipInfo.value.copy(isLoading = true, error = null)
            withContext(Dispatchers.Default) {
                if (!useProxy) {
                    LogRepository.i("Querying public IP (direct)...", "IpWhois")
                    val result = fetchParallelDirect(provider)
                    if (result != null) {
                        _ipInfo.value = result
                        LogRepository.i("Direct IP: ${result.ip} (${result.country})", "IpWhois")
                        return@withContext
                    }
                } else {
                    delay(800.milliseconds)
                    for (attempt in 1..4) {
                        LogRepository.i("Querying public IP via tunnel ($socksHost:$socksPort) attempt $attempt...", "IpWhois")
                        val result = fetchParallelViaProxy(socksHost, socksPort, provider)
                        if (result != null) {
                            _ipInfo.value = result
                            LogRepository.i("Tunnel IP: ${result.ip} (${result.country})", "IpWhois")
                            return@withContext
                        }
                        if (attempt < 4) {
                            delay((1200L * attempt).milliseconds)
                        }
                    }
                    LogRepository.w("SOCKS proxy lookup failed after all attempts.", "IpWhois")
                }
                LogRepository.w("${if (useProxy) "SOCKS proxy" else "Direct"} IP lookup failed after all attempts.", "IpWhois")
                val prev = _ipInfo.value
                _ipInfo.value = prev.copy(
                    isLoading = false,
                    error = if (prev.ip.isEmpty()) if (useProxy) "Proxy Lookup Failed" else "Direct Lookup Failed" else null
                )
                if (prev.ip.isNotEmpty()) {
                    _ipInfo.value = prev.copy(isLoading = false, error = null)
                }
            }
        } finally {
            mutex.unlock()
        }
    }

    private suspend fun fetchParallelDirect(provider: IpInfoProvider = IpInfoProvider.AUTO): IpInfo? = coroutineScope {
        val all = directSources()
        val ordered = if (provider == IpInfoProvider.AUTO) all.shuffled() else all.filter { it.first == provider }
        if (ordered.isEmpty()) return@coroutineScope null
        val sources = ordered.map { async { it.second() } }
        for (future in sources) {
            val result = future.await()
            if (result != null) {
                sources.forEach { it.cancel() }
                return@coroutineScope result
            }
        }
        null
    }

    private suspend fun fetchParallelViaProxy(socksHost: String, socksPort: Int, provider: IpInfoProvider = IpInfoProvider.AUTO): IpInfo? = coroutineScope {
        val all = proxySources(socksHost, socksPort)
        val ordered = if (provider == IpInfoProvider.AUTO) all.shuffled() else all.filter { it.first == provider }
        if (ordered.isEmpty()) return@coroutineScope null
        val sources = ordered.map { async { it.second() } }
        for (future in sources) {
            val result = future.await()
            if (result != null) {
                sources.forEach { it.cancel() }
                return@coroutineScope result
            }
        }
        null
    }

    private fun tryViaProxyIpSb(socksHost: String, socksPort: Int): IpInfo? {
        return try {
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
            val client = NetworkClient.instance.newBuilder()
                .proxy(proxy)
                .connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .build()

            val request = Request.Builder()
                .url("https://api.ip.sb/geoip")
                .header("User-Agent", "Mozilla/5.0")
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    val country = root["country"]?.jsonPrimitive?.content ?: "Unknown"
                    val countryCode = root["country_code"]?.jsonPrimitive?.content ?: ""

                    if (ip.isNotEmpty()) {
                        LogRepository.i("Geo-data (ip.sb): $ip ($country)", "IpWhois")
                        IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false)
                    } else null
                } else null
            }
        } catch (e: Throwable) {
            LogRepository.w("ip.sb via SOCKS error: ${e.message}", "IpWhois")
            null
        }
    }

    private fun tryViaProxyIpify(socksHost: String, socksPort: Int): IpInfo? {
        return try {
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
            val client = NetworkClient.instance.newBuilder()
                .proxy(proxy)
                .connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .build()

            val request = Request.Builder()
                .url("https://api.ipify.org?format=json")
                .header("User-Agent", "Mozilla/5.0")
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""

                    if (ip.isNotEmpty()) {
                        LogRepository.i("IP via ipify: $ip", "IpWhois")
                        IpInfo(ip, "Unknown", "", getFlagEmoji(""), false)
                    } else null
                } else null
            }
        } catch (e: Throwable) {
            LogRepository.w("ipify via SOCKS error: ${e.message}", "IpWhois")
            null
        }
    }

    private fun tryViaProxyIfconfig(socksHost: String, socksPort: Int): IpInfo? {
        return try {
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
            val client = NetworkClient.instance.newBuilder()
                .proxy(proxy)
                .connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .build()

            val request = Request.Builder()
                .url("https://ifconfig.me/all.json")
                .header("User-Agent", "Mozilla/5.0")
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip_addr"]?.jsonPrimitive?.content ?: ""
                    val countryCode = root["country_code"]?.jsonPrimitive?.content ?: ""

                    if (ip.isNotEmpty()) {
                        LogRepository.i("IP via ifconfig: $ip", "IpWhois")
                        IpInfo(ip, "Unknown", countryCode, getFlagEmoji(countryCode), false)
                    } else null
                } else null
            }
        } catch (e: Throwable) {
            LogRepository.w("ifconfig.me via SOCKS error: ${e.message}", "IpWhois")
            null
        }
    }

    private fun tryViaProxyAmazon(socksHost: String, socksPort: Int): IpInfo? {
        return try {
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
            val client = NetworkClient.instance.newBuilder()
                .proxy(proxy)
                .connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .build()

            val request = Request.Builder()
                .url("https://checkip.amazonaws.com")
                .header("User-Agent", "curl/7.64.1")
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val ip = response.body?.string()?.trim() ?: ""
                    if (ip.isNotEmpty()) {
                        LogRepository.i("IP via Amazon: $ip", "IpWhois")
                        IpInfo(ip, "Unknown", "", getFlagEmoji(""), false)
                    } else null
                } else null
            }
        } catch (e: Throwable) {
            LogRepository.w("Amazon IP check failed: ${e.message}", "IpWhois")
            null
        }
    }

    private fun tryViaProxyIpinfoIo(socksHost: String, socksPort: Int): IpInfo? {
        return try {
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
            val client = NetworkClient.instance.newBuilder()
                .proxy(proxy)
                .connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .build()

            val request = Request.Builder()
                .url("https://ipinfo.io/json")
                .header("User-Agent", "Mozilla/5.0")
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    val country = root["country"]?.jsonPrimitive?.content ?: "Unknown"
                    val countryCode = root["country"]?.jsonPrimitive?.content ?: ""

                    if (ip.isNotEmpty()) {
                        LogRepository.i("IP via ipinfo.io: $ip ($country)", "IpWhois")
                        IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false)
                    } else null
                } else null
            }
        } catch (e: Throwable) {
            LogRepository.w("ipinfo.io via SOCKS error: ${e.message}", "IpWhois")
            null
        }
    }

    private fun tryDirectIpSb(): IpInfo? {
        return try {
            val client = NetworkClient.instance.newBuilder()
                .connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .build()
            val request = Request.Builder().url("https://api.ip.sb/geoip").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    if (ip.isNotEmpty()) {
                        val country = root["country"]?.jsonPrimitive?.content ?: "Unknown"
                        val countryCode = root["country_code"]?.jsonPrimitive?.content ?: ""
                        IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false)
                    } else null
                } else null
            }
        } catch (_: Throwable) { null }
    }

    private fun tryDirectIpify(): IpInfo? {
        return try {
            val client = NetworkClient.instance.newBuilder()
                .connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .build()
            val request = Request.Builder().url("https://api.ipify.org?format=json").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    if (ip.isNotEmpty()) IpInfo(ip, "Unknown", "", getFlagEmoji(""), false) else null
                } else null
            }
        } catch (_: Throwable) { null }
    }

    private fun tryDirectIpinfoIo(): IpInfo? {
        return try {
            val client = NetworkClient.instance.newBuilder()
                .connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .build()
            val request = Request.Builder().url("https://ipinfo.io/json").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    val country = root["country"]?.jsonPrimitive?.content ?: "Unknown"
                    val countryCode = root["country"]?.jsonPrimitive?.content ?: ""
                    if (ip.isNotEmpty()) IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false) else null
                } else null
            }
        } catch (_: Throwable) { null }
    }

    private fun tryDirectIfconfig(): IpInfo? {
        return try {
            val client = NetworkClient.instance.newBuilder()
                .connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .build()
            val request = Request.Builder().url("https://ifconfig.me/all.json").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip_addr"]?.jsonPrimitive?.content ?: ""
                    val countryCode = root["country_code"]?.jsonPrimitive?.content ?: ""
                    if (ip.isNotEmpty()) IpInfo(ip, "Unknown", countryCode, getFlagEmoji(countryCode), false) else null
                } else null
            }
        } catch (_: Throwable) { null }
    }

    private fun tryViaProxyIpWhoIs(socksHost: String, socksPort: Int): IpInfo? {
        return try {
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
            val client = NetworkClient.instance.newBuilder().proxy(proxy).connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            val request = Request.Builder().url("https://ipwho.is/").header("User-Agent", "Mozilla/5.0").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    val country = root["country"]?.jsonPrimitive?.content ?: "Unknown"
                    val countryCode = root["country_code"]?.jsonPrimitive?.content ?: ""
                    if (ip.isNotEmpty()) {
                        LogRepository.i("Geo-data (ipwho.is): $ip ($country)", "IpWhois")
                        IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false)
                    } else null
                } else null
            }
        } catch (e: Throwable) {
            LogRepository.w("ipwho.is via SOCKS error: ${e.message}", "IpWhois")
            null
        }
    }

    private fun tryViaProxyFreeIpApi(socksHost: String, socksPort: Int): IpInfo? {
        return try {
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
            val client = NetworkClient.instance.newBuilder().proxy(proxy).connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            val request = Request.Builder().url("https://freeipapi.com/api/json").header("User-Agent", "Mozilla/5.0").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ipAddress"]?.jsonPrimitive?.content ?: ""
                    val countryCode = root["countryCode"]?.jsonPrimitive?.content ?: ""
                    val country = root["countryName"]?.jsonPrimitive?.content ?: "Unknown"
                    if (ip.isNotEmpty()) {
                        LogRepository.i("Geo-data (freeipapi): $ip ($country)", "IpWhois")
                        IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false)
                    } else null
                } else null
            }
        } catch (e: Throwable) {
            LogRepository.w("freeipapi via SOCKS error: ${e.message}", "IpWhois")
            null
        }
    }

    private fun tryDirectIpWhoIs(): IpInfo? {
        return try {
            val client = NetworkClient.instance.newBuilder().connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            val request = Request.Builder().url("https://ipwho.is/").header("User-Agent", "Mozilla/5.0").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    val country = root["country"]?.jsonPrimitive?.content ?: "Unknown"
                    val countryCode = root["country_code"]?.jsonPrimitive?.content ?: ""
                    if (ip.isNotEmpty()) IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false) else null
                } else null
            }
        } catch (_: Throwable) { null }
    }

    private fun tryDirectFreeIpApi(): IpInfo? {
        return try {
            val client = NetworkClient.instance.newBuilder().connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            val request = Request.Builder().url("https://freeipapi.com/api/json").header("User-Agent", "Mozilla/5.0").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ipAddress"]?.jsonPrimitive?.content ?: ""
                    val countryCode = root["countryCode"]?.jsonPrimitive?.content ?: ""
                    val country = root["countryName"]?.jsonPrimitive?.content ?: "Unknown"
                    if (ip.isNotEmpty()) IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false) else null
                } else null
            }
        } catch (_: Throwable) { null }
    }

    private fun tryViaProxyGeojs(socksHost: String, socksPort: Int): IpInfo? {
        return try {
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
            val client = NetworkClient.instance.newBuilder().proxy(proxy).connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            val request = Request.Builder().url("https://get.geojs.io/v1/ip/geo.json").header("User-Agent", "Mozilla/5.0").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    val country = root["country"]?.jsonPrimitive?.content ?: "Unknown"
                    val countryCode = root["country_code"]?.jsonPrimitive?.content ?: ""
                    if (ip.isNotEmpty()) {
                        LogRepository.i("Geo-data (geojs.io): $ip ($country)", "IpWhois")
                        IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false)
                    } else null
                } else null
            }
        } catch (e: Throwable) {
            LogRepository.w("geojs.io via SOCKS error: ${e.message}", "IpWhois")
            null
        }
    }

    private fun tryViaProxyReallyFree(socksHost: String, socksPort: Int): IpInfo? {
        return try {
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
            val client = NetworkClient.instance.newBuilder().proxy(proxy).connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            val request = Request.Builder().url("https://reallyfreegeoip.org/json/").header("User-Agent", "Mozilla/5.0").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    val country = root["country_name"]?.jsonPrimitive?.content ?: "Unknown"
                    val countryCode = root["country_code"]?.jsonPrimitive?.content ?: ""
                    if (ip.isNotEmpty()) {
                        LogRepository.i("Geo-data (reallyfreegeoip): $ip ($country)", "IpWhois")
                        IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false)
                    } else null
                } else null
            }
        } catch (e: Throwable) {
            LogRepository.w("reallyfreegeoip via SOCKS error: ${e.message}", "IpWhois")
            null
        }
    }

    private fun tryViaProxyGeoIpLookup(socksHost: String, socksPort: Int): IpInfo? {
        return try {
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
            val client = NetworkClient.instance.newBuilder().proxy(proxy).connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            val request = Request.Builder().url("https://json.geoiplookup.io/").header("User-Agent", "Mozilla/5.0").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    val country = root["country_name"]?.jsonPrimitive?.content ?: "Unknown"
                    val countryCode = root["country_code"]?.jsonPrimitive?.content ?: ""
                    if (ip.isNotEmpty()) {
                        LogRepository.i("Geo-data (geoiplookup.io): $ip ($country)", "IpWhois")
                        IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false)
                    } else null
                } else null
            }
        } catch (e: Throwable) {
            LogRepository.w("geoiplookup.io via SOCKS error: ${e.message}", "IpWhois")
            null
        }
    }

    private fun tryViaProxyFreeFreeIpApi(socksHost: String, socksPort: Int): IpInfo? {
        return try {
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
            val client = NetworkClient.instance.newBuilder().proxy(proxy).connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            val request = Request.Builder().url("https://free.freeipapi.com/api/json").header("User-Agent", "Mozilla/5.0").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ipAddress"]?.jsonPrimitive?.content ?: ""
                    val countryCode = root["countryCode"]?.jsonPrimitive?.content ?: ""
                    val country = root["countryName"]?.jsonPrimitive?.content ?: "Unknown"
                    if (ip.isNotEmpty()) {
                        LogRepository.i("Geo-data (free.freeipapi): $ip ($country)", "IpWhois")
                        IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false)
                    } else null
                } else null
            }
        } catch (e: Throwable) {
            LogRepository.w("free.freeipapi via SOCKS error: ${e.message}", "IpWhois")
            null
        }
    }

    private fun tryDirectGeojs(): IpInfo? {
        return try {
            val client = NetworkClient.instance.newBuilder().connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            val request = Request.Builder().url("https://get.geojs.io/v1/ip/geo.json").header("User-Agent", "Mozilla/5.0").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    val country = root["country"]?.jsonPrimitive?.content ?: "Unknown"
                    val countryCode = root["country_code"]?.jsonPrimitive?.content ?: ""
                    if (ip.isNotEmpty()) IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false) else null
                } else null
            }
        } catch (_: Throwable) { null }
    }

    private fun tryDirectReallyFree(): IpInfo? {
        return try {
            val client = NetworkClient.instance.newBuilder().connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            val request = Request.Builder().url("https://reallyfreegeoip.org/json/").header("User-Agent", "Mozilla/5.0").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    val country = root["country_name"]?.jsonPrimitive?.content ?: "Unknown"
                    val countryCode = root["country_code"]?.jsonPrimitive?.content ?: ""
                    if (ip.isNotEmpty()) IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false) else null
                } else null
            }
        } catch (_: Throwable) { null }
    }

    private fun tryDirectGeoIpLookup(): IpInfo? {
        return try {
            val client = NetworkClient.instance.newBuilder().connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            val request = Request.Builder().url("https://json.geoiplookup.io/").header("User-Agent", "Mozilla/5.0").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ip"]?.jsonPrimitive?.content ?: ""
                    val country = root["country_name"]?.jsonPrimitive?.content ?: "Unknown"
                    val countryCode = root["country_code"]?.jsonPrimitive?.content ?: ""
                    if (ip.isNotEmpty()) IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false) else null
                } else null
            }
        } catch (_: Throwable) { null }
    }

    private fun tryDirectFreeFreeIpApi(): IpInfo? {
        return try {
            val client = NetworkClient.instance.newBuilder().connectTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).readTimeout(8000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            val request = Request.Builder().url("https://free.freeipapi.com/api/json").header("User-Agent", "Mozilla/5.0").build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string() ?: return null
                    val root = json.parseToJsonElement(jsonStr).jsonObject
                    val ip = root["ipAddress"]?.jsonPrimitive?.content ?: ""
                    val countryCode = root["countryCode"]?.jsonPrimitive?.content ?: ""
                    val country = root["countryName"]?.jsonPrimitive?.content ?: "Unknown"
                    if (ip.isNotEmpty()) IpInfo(ip, country, countryCode, getFlagEmoji(countryCode), false) else null
                } else null
            }
        } catch (_: Throwable) { null }
    }

    fun reset() { _ipInfo.value = IpInfo() }

    private fun getFlagEmoji(countryCode: String): String {
        if (countryCode.length != 2) return "\uD83C\uDF10"
        val firstLetter = countryCode[0].uppercaseChar().code - 'A'.code + 0x1F1E6
        val secondLetter = countryCode[1].uppercaseChar().code - 'A'.code + 0x1F1E6
        return codePointToString(firstLetter) + codePointToString(secondLetter)
    }

    private fun codePointToString(codePoint: Int): String {
        return if (codePoint <= 0xFFFF) {
            codePoint.toChar().toString()
        } else {
            val high = ((codePoint - 0x10000) shr 10) + 0xD800
            val low = ((codePoint - 0x10000) and 0x3FF) + 0xDC00
            high.toChar().toString() + low.toChar().toString()
        }
    }
}
