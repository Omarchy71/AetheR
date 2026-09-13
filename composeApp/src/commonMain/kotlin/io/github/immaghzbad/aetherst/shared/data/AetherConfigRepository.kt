package io.github.immaghzbad.aetherst.shared.data

import io.github.immaghzbad.aetherst.shared.model.*
import io.github.immaghzbad.aetherst.platform.Settings
import io.github.immaghzbad.aetherst.platform.isDesktop
import io.github.immaghzbad.aetherst.platform.isWindows
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class AetherConfigRepository private constructor(private val settings: Settings) {

    private val _config = MutableStateFlow(loadConfig())
    val config: StateFlow<AetherConfig> = _config.asStateFlow()

    private val _isOnboardingComplete = MutableStateFlow(value = settings.getBoolean("onboarding_complete", false))
    val isOnboardingComplete: StateFlow<Boolean> = _isOnboardingComplete.asStateFlow()

    companion object {
        @Volatile
        private var INSTANCE: AetherConfigRepository? = null

        fun getInstance(settings: Settings): AetherConfigRepository {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: AetherConfigRepository(settings).also { INSTANCE = it }
            }
        }
    }

    init {
        LogRepository.currentAppLogLevel = _config.value.appLogLevel
        LogRepository.currentCoreLogLevel = _config.value.coreLogLevel
    }

    private fun loadConfig(): AetherConfig {
        migrateCoreLoggingDefault()
        return try {
            readFromSettings("")
        } catch (_: Exception) {
            // Legacy config (e.g. removed protocols/fields) failed to deserialize: fall back to defaults.
            LogRepository.w("Stored config failed to load, using defaults", "AetherConfig")
            AetherConfig()
        }
    }

    private fun migrateCoreLoggingDefault() {
        if (settings.getBoolean("core_logging_default_v2", false)) return
        val current = settings.getString("core_log_level", "")
        val manual = settings.getString("manual_core_log_level", "")

        if (current.isEmpty() || (current == AetherLogLevel.OFF.name)) {
            settings.putString("core_log_level", AetherLogLevel.INFO.name)
        }
        if (manual.isEmpty() || (manual == AetherLogLevel.OFF.name)) {
            settings.putString("manual_core_log_level", AetherLogLevel.INFO.name)
        }
        settings.putBoolean("core_logging_default_v2", true)
    }

    private fun loadManualConfig(): AetherConfig {
        return try {
            readFromSettings("manual_")
        } catch (_: Exception) {
            AetherConfig()
        }
    }

    private fun storedProtocol(): AetherProtocol {
        // GOOL-only build: any legacy stored protocol (masque/wg/zt) migrates to GOOL.
        return AetherProtocol.GOOL
    }

    private fun readFromSettings(prefix: String): AetherConfig {
        val noiseStr = settings.getString("${prefix}noise", AetherNoise.FIREWALL.name)
        val scanModeStr = settings.getString("${prefix}scan_mode", AetherScanMode.BALANCED.name)
        val ipModeStr = settings.getString("${prefix}ip_mode", AetherIpMode.AUTO.name)
        val appLogLevelStr = settings.getString("${prefix}app_log_level", AetherLogLevel.INFO.name)
        val coreLogLevelStr = settings.getString("${prefix}core_log_level", AetherLogLevel.INFO.name)
        val perfProfileStr = settings.getString("${prefix}perf_profile", AetherPerfProfile.AUTO.name)
        val connectionModeStr = settings.getString("${prefix}connection_mode", "")
        val legacyProxyOnly = settings.getBoolean("${prefix}proxy_only", false)

        val connectionMode = if (connectionModeStr.isNotEmpty()) {
            runCatching { ConnectionMode.valueOf(connectionModeStr) }.getOrDefault(ConnectionMode.TUNNEL)
        } else {
            if (legacyProxyOnly) ConnectionMode.PROXY_ONLY else if (isWindows) ConnectionMode.SYSTEM_PROXY else ConnectionMode.TUNNEL
        }

        val finalConnectionMode = connectionMode

        val presetId = settings.getString("${prefix}preset_id", "custom")
        val socksHost = settings.getString("${prefix}socks_host", "127.0.0.1")
        val cleanHost = if (socksHost == "198.18.0.1") "127.0.0.1" else socksHost

        return AetherConfig(
            presetId = presetId,
            protocol = storedProtocol(),
            noise = runCatching { AetherNoise.valueOf(noiseStr) }.getOrDefault(AetherNoise.FIREWALL),
            scanMode = runCatching { AetherScanMode.valueOf(scanModeStr) }.getOrDefault(AetherScanMode.BALANCED),
            ipMode = runCatching { AetherIpMode.valueOf(ipModeStr) }.getOrDefault(AetherIpMode.AUTO),
            httpProxyEnabled = settings.getBoolean("${prefix}http_proxy_enabled", false),
            perfProfile = runCatching { AetherPerfProfile.valueOf(perfProfileStr) }.getOrDefault(AetherPerfProfile.AUTO),
            noDataCheck = settings.getBoolean("${prefix}no_data_check", false),
            quickReconnect = settings.getBoolean("${prefix}quick_reconnect", true),
            socksHost = cleanHost,
            socksPort = settings.getString("${prefix}socks_port", "1819"),
            httpPort = settings.getString("${prefix}http_port", "1820"),
            appLogLevel = runCatching { AetherLogLevel.valueOf(appLogLevelStr) }.getOrDefault(AetherLogLevel.INFO),
            coreLogLevel = runCatching { AetherLogLevel.valueOf(coreLogLevelStr) }.getOrDefault(AetherLogLevel.INFO),
            wiwOuter = settings.getString("${prefix}wiw_outer", ""),
            wiwInner = settings.getString("${prefix}wiw_inner", ""),
            wiwScan = settings.getBoolean("${prefix}wiw_scan", true),
            netstackTcpRx = settings.getInt("${prefix}netstack_tcp_rx", 0),
            netstackTcpTx = settings.getInt("${prefix}netstack_tcp_tx", 0),
            keepaliveEnabled = settings.getBoolean("${prefix}keepalive_enabled", true),
            keepalive = settings.getInt("${prefix}keepalive", 5),
            validateSecs = settings.getInt("${prefix}validate_secs", 10),
            reconnectSecs = settings.getInt("${prefix}reconnect_secs", 2),
            wgEndpointCooldownSecs = settings.getInt("${prefix}wg_endpoint_cooldown_secs", 300),
            noProfileRetry = settings.getBoolean("${prefix}no_profile_retry", false),
            tlsGroups = settings.getString("${prefix}tls_groups", ""),
            mtu = settings.getInt("${prefix}mtu", 1100),
            connectionMode = finalConnectionMode,
            routingRules = settings.getString("${prefix}routing_rules", "").let {
                if (it.isEmpty()) emptyList() else runCatching { Json.decodeFromString<List<RoutingRule>>(it) }.getOrDefault(emptyList())
            },
            smartReconnect = settings.getBoolean("${prefix}smart_reconnect", true),
            reconnectRetryLimit = settings.getInt("${prefix}reconnect_retry_limit", 10),
            dnsEnabled = settings.getBoolean("${prefix}dns_enabled", false),
            dnsList = settings.getString("${prefix}dns_list", "1.1.1.1,2606:4700:4700::1111"),
            shareHotspot = settings.getBoolean("${prefix}share_hotspot", false),
            upstreamProxy = settings.getString("${prefix}upstream_proxy", ""),
            upstreamProxyEnabled = settings.getBoolean("${prefix}upstream_proxy_enabled", false),
            routeSniffing = settings.getBoolean("${prefix}route_sniffing", true),
            sniffingTimeoutMs = settings.getInt("${prefix}sniffing_timeout_ms", 100),
            reprovision = settings.getBoolean("${prefix}reprovision", true),
            hevLogLevel = sanitizeHevLogLevel(settings.getString("${prefix}hev_log_level", "warn")),
            hevConnectTimeoutMs = settings.getInt("${prefix}hev_connect_timeout_ms", 5000),
            hevReadWriteTimeoutMs = settings.getInt("${prefix}hev_read_write_timeout_ms", 60000),
            hevMaxSessionCount = settings.getInt("${prefix}hev_max_session_count", 0),
            hevMapdnsCacheSize = settings.getInt("${prefix}hev_mapdns_cache_size", 10000),
            hevUdpMode = sanitizeHevUdpMode(settings.getString("${prefix}hev_udp_mode", "udp")),
            cloakEnabled = settings.getBoolean("${prefix}cloak_enabled", false),
            cloakSniList = settings.getString("${prefix}cloak_sni_list", "www.hcaptcha.com,www.speedtest.net,www.bing.com"),
            cloakTtlList = settings.getString("${prefix}cloak_ttl_list", "4,5,6,8"),
            cloakJitterMin = settings.getInt("${prefix}cloak_jitter_min", 20),
            cloakJitterMax = settings.getInt("${prefix}cloak_jitter_max", 80),
            cloakFragment = settings.getBoolean("${prefix}cloak_fragment", false),
            cloakAdaptive = settings.getBoolean("${prefix}cloak_adaptive", true),
            cloakFallbackPorts = settings.getString("${prefix}cloak_fallback_ports", "443,2053,2083,2087,2096,8443"),
            cloakLogLevel = sanitizeHevLogLevel(settings.getString("${prefix}cloak_log_level", "info")),
            cloakRandomizeSniCase = settings.getBoolean("${prefix}cloak_randomize_sni_case", false),
            pingUrl = sanitizePingUrl(settings.getString("${prefix}ping_url", "https://www.gstatic.com/generate_204")),
            connectButtonStyle = sanitizeConnectButtonStyle(settings.getString("${prefix}connect_button_style", "swipe")),
            appLanguage = sanitizeAppLanguage(settings.getString("${prefix}app_language", "auto")),
            tunnelAllApps = settings.getBoolean("${prefix}tunnel_all_apps", true),
            excludedPackages = settings.getStringSet("${prefix}excluded_packages", emptySet()),
            blockedPackages = settings.getStringSet("${prefix}blocked_packages", emptySet()),
            tunneledPackages = settings.getStringSet("${prefix}tunneled_packages", emptySet()),
        )
    }

    private fun sanitizeHevLogLevel(value: String): String {
        return if (value in setOf("error", "warn", "info", "debug")) value else "warn"
    }

    private fun sanitizeHevUdpMode(value: String): String {
        val v = value.lowercase().trim()
        return if (v in setOf("udp", "icmp", "off", "false")) v else "udp"
    }

    private fun sanitizePingUrl(value: String): String {
        val v = value.trim()
        if (v.isEmpty()) return "https://www.gstatic.com/generate_204"
        val lower = v.lowercase()
        if (!lower.startsWith("http://") && !lower.startsWith("https://")) return "https://www.gstatic.com/generate_204"
        val withoutScheme = v.substringAfter("://")
        val hostPart = withoutScheme.substringBefore("/").substringBefore(":")
        if (hostPart.isBlank() || !hostPart.contains(".")) return "https://www.gstatic.com/generate_204"
        return v
    }

    private fun sanitizeConnectButtonStyle(value: String): String {
        val v = value.trim().lowercase()
        return if (v == "capsule" || v == "swipe") v else "swipe"
    }

    private fun sanitizeAppLanguage(value: String): String {
        val v = value.trim().lowercase()
        return if (v == "auto" || v == "fa" || v == "en") v else "auto"
    }

    fun updateConfig(newConfig: AetherConfig) {
        val sanitized = newConfig.copy(protocol = AetherProtocol.GOOL, presetId = "custom")

        saveToSettings("", sanitized)
        saveToSettings("manual_", sanitized)
        LogRepository.currentAppLogLevel = sanitized.appLogLevel
        LogRepository.currentCoreLogLevel = sanitized.coreLogLevel
        _config.value = sanitized
    }

    fun applyDetectedConfig(newConfig: AetherConfig) {
        val manualConfig = newConfig.copy(protocol = AetherProtocol.GOOL, presetId = "custom")

        saveToSettings("", manualConfig)
        saveToSettings("manual_", manualConfig)
        LogRepository.currentAppLogLevel = manualConfig.appLogLevel
        LogRepository.currentCoreLogLevel = manualConfig.coreLogLevel
        _config.value = manualConfig
    }

    fun setOnboardingComplete(complete: Boolean) {
        settings.putBoolean("onboarding_complete", complete)
        _isOnboardingComplete.value = complete
    }

    fun getOnboardingStep(): OnboardingStep {
        val name = settings.getString("onboarding_step_name", OnboardingStep.WELCOME.name)
        return try { OnboardingStep.valueOf(name) } catch (_: Exception) { OnboardingStep.WELCOME }
    }

    fun setOnboardingStep(step: OnboardingStep) {
        settings.putString("onboarding_step_name", step.name)
    }

    private fun saveToSettings(prefix: String, cfg: AetherConfig) {
        settings.putString("${prefix}preset_id", cfg.presetId)
        settings.putString("${prefix}protocol", cfg.protocol.name)
        settings.putString("${prefix}noise", cfg.noise.name)
        settings.putString("${prefix}scan_mode", cfg.scanMode.name)
        settings.putString("${prefix}ip_mode", cfg.ipMode.name)
        settings.putBoolean("${prefix}http_proxy_enabled", cfg.httpProxyEnabled)
        settings.putString("${prefix}perf_profile", cfg.perfProfile.name)
        settings.putBoolean("${prefix}no_data_check", cfg.noDataCheck)
        settings.putBoolean("${prefix}quick_reconnect", cfg.quickReconnect)
        settings.putString("${prefix}socks_host", cfg.socksHost)
        settings.putString("${prefix}socks_port", cfg.socksPort)
        settings.putString("${prefix}http_port", cfg.httpPort)
        settings.putString("${prefix}app_log_level", cfg.appLogLevel.name)
        settings.putString("${prefix}core_log_level", cfg.coreLogLevel.name)
        settings.putString("${prefix}wiw_outer", cfg.wiwOuter)
        settings.putString("${prefix}wiw_inner", cfg.wiwInner)
        settings.putBoolean("${prefix}wiw_scan", cfg.wiwScan)
        settings.putInt("${prefix}netstack_tcp_rx", cfg.netstackTcpRx.coerceIn(0, 67108864))
        settings.putInt("${prefix}netstack_tcp_tx", cfg.netstackTcpTx.coerceIn(0, 67108864))
        settings.putBoolean("${prefix}keepalive_enabled", cfg.keepaliveEnabled)
        settings.putInt("${prefix}keepalive", cfg.keepalive)
        settings.putInt("${prefix}validate_secs", cfg.validateSecs)
        settings.putInt("${prefix}reconnect_secs", cfg.reconnectSecs)
        settings.putInt("${prefix}wg_endpoint_cooldown_secs", cfg.wgEndpointCooldownSecs)
        settings.putBoolean("${prefix}no_profile_retry", cfg.noProfileRetry)
        settings.putString("${prefix}tls_groups", cfg.tlsGroups)
        settings.putInt("${prefix}mtu", cfg.mtu)
        settings.putString("${prefix}connection_mode", cfg.connectionMode.name)
        settings.putString("${prefix}routing_rules", Json.encodeToString(cfg.routingRules))
        settings.putBoolean("${prefix}smart_reconnect", cfg.smartReconnect)
        settings.putInt("${prefix}reconnect_retry_limit", cfg.reconnectRetryLimit)
        settings.putBoolean("${prefix}dns_enabled", cfg.dnsEnabled)
        settings.putString("${prefix}dns_list", cfg.dnsList)
        settings.putBoolean("${prefix}share_hotspot", cfg.shareHotspot)
        settings.putString("${prefix}upstream_proxy", cfg.upstreamProxy)
        settings.putBoolean("${prefix}upstream_proxy_enabled", cfg.upstreamProxyEnabled)
        settings.putBoolean("${prefix}route_sniffing", cfg.routeSniffing)
        settings.putInt("${prefix}sniffing_timeout_ms", cfg.sniffingTimeoutMs)
        settings.putBoolean("${prefix}reprovision", cfg.reprovision)
        settings.putString("${prefix}hev_log_level", sanitizeHevLogLevel(cfg.hevLogLevel))
        settings.putInt("${prefix}hev_connect_timeout_ms", cfg.hevConnectTimeoutMs.coerceIn(500, 120000))
        settings.putInt("${prefix}hev_read_write_timeout_ms", cfg.hevReadWriteTimeoutMs.coerceIn(1000, 600000))
        settings.putInt("${prefix}hev_max_session_count", cfg.hevMaxSessionCount.coerceIn(0, 200000))
        settings.putInt("${prefix}hev_mapdns_cache_size", cfg.hevMapdnsCacheSize.coerceIn(100, 1000000))
        settings.putString("${prefix}hev_udp_mode", sanitizeHevUdpMode(cfg.hevUdpMode))
        settings.putBoolean("${prefix}cloak_enabled", cfg.cloakEnabled)
        settings.putString("${prefix}cloak_sni_list", cfg.cloakSniList)
        settings.putString("${prefix}cloak_ttl_list", cfg.cloakTtlList)
        settings.putInt("${prefix}cloak_jitter_min", cfg.cloakJitterMin.coerceIn(5, 500))
        settings.putInt("${prefix}cloak_jitter_max", cfg.cloakJitterMax.coerceIn(10, 1000))
        settings.putBoolean("${prefix}cloak_fragment", cfg.cloakFragment)
        settings.putBoolean("${prefix}cloak_adaptive", cfg.cloakAdaptive)
        settings.putString("${prefix}cloak_fallback_ports", cfg.cloakFallbackPorts)
        settings.putString("${prefix}cloak_log_level", sanitizeHevLogLevel(cfg.cloakLogLevel))
        settings.putBoolean("${prefix}cloak_randomize_sni_case", cfg.cloakRandomizeSniCase)
        settings.putString("${prefix}ping_url", sanitizePingUrl(cfg.pingUrl))
        settings.putString("${prefix}connect_button_style", sanitizeConnectButtonStyle(cfg.connectButtonStyle))
        settings.putString("${prefix}app_language", sanitizeAppLanguage(cfg.appLanguage))
        settings.putBoolean("${prefix}tunnel_all_apps", cfg.tunnelAllApps)
        settings.putStringSet("${prefix}excluded_packages", cfg.excludedPackages)
        settings.putStringSet("${prefix}blocked_packages", cfg.blockedPackages)
        settings.putStringSet("${prefix}tunneled_packages", cfg.tunneledPackages)
    }

    fun resetToDefaults() {
        val defaultConfig = AetherConfig()
        updateConfig(defaultConfig)
        LogRepository.i("System reset: All settings restored to factory defaults")
    }

    fun getFullConfigJson(): String {
        val sanitized = _config.value.copy(
            excludedPackages = emptySet(),
            blockedPackages = emptySet(),
            tunneledPackages = emptySet(),
            routingRules = emptyList()
        )
        return Json.encodeToString(sanitized)
    }

    fun restoreFullConfig(json: String): Boolean {
        return try {
            val restored = Json.decodeFromString<AetherConfig>(json).copy(
                protocol = AetherProtocol.GOOL,
                excludedPackages = emptySet(),
                blockedPackages = emptySet(),
                tunneledPackages = emptySet(),
                routingRules = emptyList()
            )
            updateConfig(restored)
            LogRepository.i("Full configuration restored from backup")
            true
        } catch (_: Exception) {
            false
        }
    }

    fun applyPreset(presetId: String) {
        val current = _config.value
        if (presetId == "custom") {
            val manual = loadManualConfig().copy(presetId = "custom")
            saveToSettings("", manual)
            LogRepository.i("Configuration profile applied: custom")
            LogRepository.currentAppLogLevel = manual.appLogLevel
            LogRepository.currentCoreLogLevel = manual.coreLogLevel
            _config.value = manual
            return
        }
        var updated = when (presetId) {
            "turbo" -> current.copy(
                presetId = "turbo",
                protocol = AetherProtocol.GOOL,
                noise = AetherNoise.GFW,
                scanMode = AetherScanMode.TURBO,
                httpProxyEnabled = false,
                noDataCheck = false,
                tlsGroups = "",
                mtu = 1320,
                connectionMode = ConnectionMode.TUNNEL
            )
            "thorough" -> current.copy(
                presetId = "thorough",
                protocol = AetherProtocol.GOOL,
                noise = AetherNoise.GFW,
                scanMode = AetherScanMode.TURBO,
                httpProxyEnabled = false,
                noDataCheck = false,
                tlsGroups = "",
                mtu = 1320,
                connectionMode = ConnectionMode.TUNNEL
            )
            "stealth" -> current.copy(
                presetId = "stealth",
                protocol = AetherProtocol.GOOL,
                noise = AetherNoise.AGGRESSIVE,
                scanMode = AetherScanMode.STEALTH,
                httpProxyEnabled = true,
                noDataCheck = false,
                tlsGroups = "",
                mtu = 1330,
                connectionMode = ConnectionMode.TUNNEL
            )
            "ironclad" -> current.copy(
                presetId = "ironclad",
                protocol = AetherProtocol.GOOL,
                noise = AetherNoise.AGGRESSIVE,
                scanMode = AetherScanMode.STEALTH,
                httpProxyEnabled = true,
                noDataCheck = false,
                tlsGroups = "",
                mtu = 1330,
                connectionMode = ConnectionMode.TUNNEL
            )
            else -> return
        }
        LogRepository.i("Configuration profile applied: $presetId")
        saveToSettings("", updated)
        saveToSettings("manual_", updated)
        LogRepository.currentAppLogLevel = updated.appLogLevel
        LogRepository.currentCoreLogLevel = updated.coreLogLevel
        _config.value = updated
    }
}
