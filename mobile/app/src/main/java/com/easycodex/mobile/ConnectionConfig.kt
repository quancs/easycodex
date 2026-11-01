package com.easycodex.mobile

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

data class EasyCodexConnectionConfig(
    val relayUrl: String,
    val apiKey: String,
    val e2eRequired: Boolean = false,
)

const val PREF_RELAY_HOST_PROFILES = "relay_host_profiles"
const val PREF_ACTIVE_RELAY_HOST_ID = "active_relay_host_id"

fun parseEasyCodexConnectionUri(raw: String?): EasyCodexConnectionConfig? {
    val uri = runCatching { URI(raw?.trim().orEmpty()) }.getOrNull() ?: return null
    val scheme = uri.scheme?.lowercase(Locale.ROOT).orEmpty()
    val isDeepLink = scheme == "easycodex" && uri.host.equals("connect", ignoreCase = true)
    val isHttpConnect = (scheme == "http" || scheme == "https") &&
        (uri.path.equals("/c", ignoreCase = true) || uri.path.equals("/connect", ignoreCase = true))

    if (!isDeepLink && !isHttpConnect) return null

    val query = parseQueryParameters(uri.rawQuery)
    val relayUrl = firstQueryParameter(query, "relayUrl", "webSocketUrl", "wsUrl", "url")
        ?: inferRelayUrlFromHttpConnectUri(uri, scheme)
        ?: return null
    val apiKey = firstQueryParameter(query, "apiKey", "key", "k") ?: return null
    if (!relayUrl.startsWith("ws://", ignoreCase = true) && !relayUrl.startsWith("wss://", ignoreCase = true)) {
        return null
    }
    if (validateRelayEndpoint(relayUrl, "") != null) return null

    // 二维码/深链携带 e2e=1 → 该主机强制 E2E 加密握手（不回落明文）
    val e2eRequired = firstQueryParameter(query, "e2e") in setOf("1", "true")
    return EasyCodexConnectionConfig(relayUrl = relayUrl, apiKey = apiKey, e2eRequired = e2eRequired)
}

fun relayHostIdFor(relayUrl: String): String {
    val uri = runCatching { URI(relayUrl.trim()) }.getOrNull()
    val host = uri?.host?.lowercase(Locale.ROOT).orEmpty().ifBlank { relayUrl.trim().lowercase(Locale.ROOT) }
    val port = uri?.port?.takeIf { it > 0 }?.toString().orEmpty()
    val scheme = uri?.scheme?.lowercase(Locale.ROOT).orEmpty()
    return listOf(scheme, host, port).filter { it.isNotBlank() }.joinToString("_")
        .replace(Regex("[^a-z0-9_.-]"), "_")
        .ifBlank { "relay_host" }
}

fun relayHostNameFor(relayUrl: String): String {
    val uri = runCatching { URI(relayUrl.trim()) }.getOrNull()
    val host = uri?.host?.takeIf { it.isNotBlank() } ?: return "EasyCodex Relay"
    return listOfNotNull(host, uri.port.takeIf { it > 0 }?.toString()).joinToString(":")
}

fun parseRelayHostProfiles(raw: String?): List<RelayHostProfile> {
    if (raw.isNullOrBlank()) return emptyList()
    val array = runCatching { JSONArray(raw) }.getOrNull() ?: return emptyList()
    return buildList {
        for (index in 0 until array.length()) {
            val json = array.optJSONObject(index) ?: continue
            val relayUrl = json.optString("relayUrl").trim()
            val apiKey = json.optString("apiKey").trim()
            if (relayUrl.isBlank() || apiKey.isBlank()) continue
            add(
                RelayHostProfile(
                    id = json.optString("id").ifBlank { relayHostIdFor(relayUrl) },
                    name = json.optString("name").ifBlank { relayHostNameFor(relayUrl) },
                    relayUrl = relayUrl,
                    apiKey = apiKey,
                    e2eRequired = json.optBoolean("e2e", false),
                    hostname = json.optString("hostname"),
                    platform = json.optString("platform"),
                    workspaceRoot = json.optString("workspaceRoot"),
                    lastSeen = json.optLong("lastSeen", 0L),
                    warnings = json.optJSONArray("warnings")?.let { warnings ->
                        buildList {
                            for (warningIndex in 0 until warnings.length()) {
                                warnings.optString(warningIndex).takeIf { it.isNotBlank() }?.let(::add)
                            }
                        }
                    } ?: emptyList(),
                ),
            )
        }
    }.distinctBy { it.id }
}

fun serializeRelayHostProfiles(profiles: List<RelayHostProfile>): String {
    val array = JSONArray()
    profiles.distinctBy { it.id }.forEach { profile ->
        array.put(
            JSONObject()
                .put("id", profile.id)
                .put("name", profile.name)
                .put("relayUrl", profile.relayUrl)
                .put("apiKey", profile.apiKey)
                .put("e2e", profile.e2eRequired)
                .put("hostname", profile.hostname)
                .put("platform", profile.platform)
                .put("workspaceRoot", profile.workspaceRoot)
                .put("lastSeen", profile.lastSeen)
                .put("warnings", JSONArray(profile.warnings)),
        )
    }
    return array.toString()
}

fun upsertRelayHostProfile(profiles: List<RelayHostProfile>, profile: RelayHostProfile): List<RelayHostProfile> {
    val next = profiles.filterNot { it.id == profile.id }.toMutableList()
    next.add(0, profile)
    return next
}

fun profileFromConnectionConfig(config: EasyCodexConnectionConfig): RelayHostProfile {
    return RelayHostProfile(
        id = relayHostIdFor(config.relayUrl),
        name = relayHostNameFor(config.relayUrl),
        relayUrl = config.relayUrl,
        apiKey = config.apiKey,
        e2eRequired = config.e2eRequired,
    )
}

fun saveRelayHostProfile(
    prefs: android.content.SharedPreferences,
    profile: RelayHostProfile,
    makeActive: Boolean = true,
) {
    val profiles = parseRelayHostProfiles(prefs.getString(PREF_RELAY_HOST_PROFILES, "[]"))
    val editor = prefs.edit()
        .putString(PREF_RELAY_HOST_PROFILES, serializeRelayHostProfiles(upsertRelayHostProfile(profiles, profile)))
    if (makeActive) {
        editor
            .putString(PREF_ACTIVE_RELAY_HOST_ID, profile.id)
            .putString(PREF_RELAY_URL, profile.relayUrl)
            .putString(PREF_API_KEY, profile.apiKey)
            .putBoolean(PREF_E2E_REQUIRED, profile.e2eRequired)
    }
    editor.apply()
}

fun validateRelayEndpoint(value: String, strings: AppStrings): String? {
    return validateRelayEndpoint(value, strings.invalidRelayUrl)
}

fun validateRelayEndpoint(value: String, invalidRelayUrl: String): String? {
    val uri = runCatching { URI(value.trim()) }.getOrNull() ?: return invalidRelayUrl
    val scheme = uri.scheme?.lowercase(Locale.ROOT).orEmpty()
    val host = uri.host?.lowercase(Locale.ROOT).orEmpty()
    if (host.isBlank()) return invalidRelayUrl
    if (scheme == "wss") return null
    if (scheme != "ws") return "Relay 地址必须使用 ws:// 或 wss://"
    // E2E v1：业务帧端到端加密（apiKey 不上线），公网 ws:// 经 frp 等中转亦安全，放行
    return null
}

private fun inferRelayUrlFromHttpConnectUri(uri: URI, scheme: String): String? {
    val host = uri.host?.takeIf { it.isNotBlank() } ?: return null
    val relayScheme = when (scheme) {
        "https" -> "wss"
        "http" -> "ws"
        else -> return null
    }
    val port = if (uri.port > 0) ":${uri.port}" else ""
    return "$relayScheme://$host$port"
}

private fun parseQueryParameters(rawQuery: String?): Map<String, String> {
    if (rawQuery.isNullOrBlank()) return emptyMap()
    val values = linkedMapOf<String, String>()
    rawQuery.split("&").forEach { part ->
        val separator = part.indexOf("=")
        if (separator < 0) return@forEach
        val key = decodeQueryValue(part.substring(0, separator)).takeIf { it.isNotBlank() } ?: return@forEach
        val value = decodeQueryValue(part.substring(separator + 1)).trim()
        values.putIfAbsent(key, value)
    }
    return values
}

private fun decodeQueryValue(value: String): String {
    return runCatching { URLDecoder.decode(value, StandardCharsets.UTF_8.name()) }.getOrDefault(value)
}

private fun firstQueryParameter(query: Map<String, String>, vararg names: String): String? {
    for (name in names) {
        query[name]?.takeIf { it.isNotBlank() }?.let { return it }
    }
    return null
}
