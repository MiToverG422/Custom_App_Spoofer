#include "zygisk.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <dobby.h>
#include <elf.h>
#include <fcntl.h>
#include <jni.h>
#include <link.h>
#include <lsplant.hpp>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if __has_include(<sys/sysmacros.h>)
#include <sys/sysmacros.h>
#endif

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cstring>
#include <ctime>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

constexpr const char *kLogTag = "OOSRegionFaker";
constexpr const char *kConfigPath = "config/config.toml";
constexpr const char *kHookerDexPath = "hooker.dex";
constexpr const char *kLogDirPath = "logs";
constexpr const char *kLogFilePath = "logs/runtime.log";
constexpr const char *kAbsoluteLogFilePath = "/data/adb/modules/custom_app_spoofer/logs/runtime.log";
constexpr const char *kAppFeatureProviderAuthority =
        "com.oplus.customize.coreapp.configmanager.configprovider.AppFeatureProvider";

void moduleLog(android_LogPriority priority, const char *fmt, ...);

#define LOGI(...) moduleLog(ANDROID_LOG_INFO, __VA_ARGS__)
#define LOGW(...) moduleLog(ANDROID_LOG_WARN, __VA_ARGS__)

struct AppRule {
    std::string package_name;
    std::string profile_name;
    bool enabled = false;
};

struct Profile {
    std::unordered_map<std::string, std::string> properties;
    std::unordered_map<std::string, std::string> build_fields;
    std::unordered_map<std::string, std::string> app_features;
    std::string locale_language;
    std::string locale_country;
};

struct RuntimeConfig {
    std::vector<AppRule> apps;
    std::unordered_map<std::string, Profile> profiles;
    std::string default_profile = "default_OOSLocalizerCN";
    bool log = false;
    bool log_file = false;
    bool log_unmatched = false;
    bool art_hooks = true;
    bool native_property_hook = false;
    bool allow_wildcard_heavy_hooks = false;
    bool log_hook_hits = false;
    long log_max_bytes = 262144;
};

struct ActiveConfig {
    bool enabled = false;
    bool log = false;
    bool log_file = false;
    bool log_unmatched = false;
    bool art_hooks = true;
    bool native_property_hook = false;
    bool allow_wildcard_heavy_hooks = false;
    bool log_hook_hits = false;
    bool matched_wildcard = false;
    long log_max_bytes = 262144;
    std::string package_name;
    std::string process_name;
    std::string profile_name;
    Profile profile;
};

using NativeGet1 = jstring (*)(JNIEnv *, jclass, jstring);
using NativeGet2 = jstring (*)(JNIEnv *, jclass, jstring, jstring);
using NativeGetBoolean = jboolean (*)(JNIEnv *, jclass, jstring, jboolean);
using NativeGetInt = jint (*)(JNIEnv *, jclass, jstring, jint);
using NativeGetLong = jlong (*)(JNIEnv *, jclass, jstring, jlong);
using SystemPropertyGet = int (*)(const char *, char *);

enum class HookKind {
    AppFeatureMethod,
    ContentResolverQuery,
};

struct MethodHookRecord {
    int id = 0;
    HookKind kind = HookKind::AppFeatureMethod;
    jobject backup_method = nullptr;
    bool is_static = false;
    std::string return_type;
};

class ArtElfResolver;

ActiveConfig g_active;
zygisk::Api *g_api = nullptr;
NativeGet1 g_orig_native_get1 = nullptr;
NativeGet2 g_orig_native_get2 = nullptr;
NativeGetBoolean g_orig_native_get_boolean = nullptr;
NativeGetInt g_orig_native_get_int = nullptr;
NativeGetLong g_orig_native_get_long = nullptr;
SystemPropertyGet g_orig_system_property_get = nullptr;
std::vector<MethodHookRecord> g_method_hooks;
jclass g_hook_bridge_class = nullptr;
jmethodID g_hook_bridge_ctor = nullptr;
jobject g_hook_bridge_callback_method = nullptr;
bool g_hook_bridge_ready = false;
bool g_lsplant_initialized = false;
bool g_lsplant_attempted = false;
bool g_art_hooks_installed = false;
ArtElfResolver *g_art_resolver = nullptr;
int g_log_fd = -1;

bool writeAll(int fd, const char *data, size_t size) {
    while (size > 0) {
        const ssize_t written = TEMP_FAILURE_RETRY(write(fd, data, size));
        if (written <= 0) return false;
        data += written;
        size -= static_cast<size_t>(written);
    }
    return true;
}

void trimLogFileIfNeeded(const char *path, long max_bytes) {
    if (max_bytes <= 0) return;
    struct stat st = {};
    if (stat(path, &st) == 0 && st.st_size > max_bytes) {
        const int fd = TEMP_FAILURE_RETRY(open(path, O_WRONLY | O_TRUNC | O_CLOEXEC));
        if (fd >= 0) close(fd);
    }
}

void appendLineToAbsoluteLog(const char *line, size_t length, long max_bytes) {
    mkdir("/data/adb/modules/custom_app_spoofer/logs", 0755);
    trimLogFileIfNeeded(kAbsoluteLogFilePath, max_bytes);
    const int fd = TEMP_FAILURE_RETRY(open(
            kAbsoluteLogFilePath,
            O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
            0644));
    if (fd < 0) return;
    writeAll(fd, line, length);
    close(fd);
}

void companionLogHandler(int client) {
    std::string payload;
    char buffer[512];
    for (;;) {
        const ssize_t count = TEMP_FAILURE_RETRY(read(client, buffer, sizeof(buffer)));
        if (count <= 0) break;
        payload.append(buffer, static_cast<size_t>(count));
        if (payload.size() > 4096) break;
    }
    if (!payload.empty()) {
        appendLineToAbsoluteLog(payload.data(), payload.size(), 262144);
    }
    close(client);
}

void sendLineToCompanion(const char *line, size_t length) {
    if (g_api == nullptr || length == 0) return;
    const int fd = g_api->connectCompanion();
    if (fd < 0) return;
    writeAll(fd, line, length);
    close(fd);
}

void moduleLog(android_LogPriority priority, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list logcat_args;
    va_copy(logcat_args, args);
    __android_log_vprint(priority, kLogTag, fmt, logcat_args);
    va_end(logcat_args);

    if (g_log_fd != -1) {
        char message[1536];
        vsnprintf(message, sizeof(message), fmt, args);

        char timestamp[32] = {};
        time_t now = time(nullptr);
        struct tm local = {};
        localtime_r(&now, &local);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &local);

        const char *level = priority >= ANDROID_LOG_WARN ? "W" : "I";
        char line[1800];
        const int length = snprintf(
                line,
                sizeof(line),
                "%s [%s] pid=%d pkg=%s process=%s %s\n",
                timestamp,
                level,
                getpid(),
                g_active.package_name.empty() ? "-" : g_active.package_name.c_str(),
                g_active.process_name.empty() ? "-" : g_active.process_name.c_str(),
                message);
        if (length > 0) {
            const size_t write_len = std::min(static_cast<size_t>(length), sizeof(line) - 1);
            if (g_log_fd >= 0) writeAll(g_log_fd, line, write_len);
            sendLineToCompanion(line, write_len);
        }
    }

    va_end(args);
}

std::string trim(std::string value) {
    auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    });
    auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) {
        return std::isspace(c) != 0;
    }).base();
    if (first >= last) return {};
    return std::string(first, last);
}

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string stripComment(const std::string &line) {
    bool quoted = false;
    char quote_char = '\0';
    bool escaped = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (quoted && c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '"' || c == '\'') {
            if (!quoted) {
                quoted = true;
                quote_char = c;
            } else if (quote_char == c) {
                quoted = false;
            }
            continue;
        }
        if (!quoted && c == '#') return line.substr(0, i);
    }
    return line;
}

std::string unquote(std::string value) {
    value = trim(std::move(value));
    if (value.size() >= 2) {
        const char first = value.front();
        const char last = value.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            std::string out;
            out.reserve(value.size() - 2);
            bool escaped = false;
            for (size_t i = 1; i + 1 < value.size(); ++i) {
                const char c = value[i];
                if (escaped) {
                    switch (c) {
                        case 'n': out.push_back('\n'); break;
                        case 'r': out.push_back('\r'); break;
                        case 't': out.push_back('\t'); break;
                        default: out.push_back(c); break;
                    }
                    escaped = false;
                } else if (first == '"' && c == '\\') {
                    escaped = true;
                } else {
                    out.push_back(c);
                }
            }
            return out;
        }
    }
    return value;
}

bool parseBool(std::string value, bool fallback) {
    value = toLower(trim(std::move(value)));
    if (value == "true" || value == "1" || value == "yes" || value == "on") return true;
    if (value == "false" || value == "0" || value == "no" || value == "off") return false;
    return fallback;
}

long parseLong(std::string value, long fallback) {
    value = trim(std::move(value));
    char *end = nullptr;
    const long parsed = strtol(value.c_str(), &end, 10);
    return end != value.c_str() && *end == '\0' ? parsed : fallback;
}

bool hasArrayEnd(const std::string &value) {
    bool quoted = false;
    char quote_char = '\0';
    bool escaped = false;
    for (char c : value) {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (quoted && c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '"' || c == '\'') {
            if (!quoted) {
                quoted = true;
                quote_char = c;
            } else if (quote_char == c) {
                quoted = false;
            }
            continue;
        }
        if (!quoted && c == ']') return true;
    }
    return false;
}

std::vector<std::string> parseStringArray(std::string value) {
    std::vector<std::string> out;
    value = trim(std::move(value));
    if (value.empty() || value.front() != '[') return out;

    const size_t begin = value.find('[');
    const size_t end = value.rfind(']');
    if (begin == std::string::npos || end == std::string::npos || begin >= end) return out;

    std::string token;
    bool quoted = false;
    char quote_char = '\0';
    bool escaped = false;
    bool unquoted_token = false;
    for (size_t i = begin + 1; i < end; ++i) {
        const char c = value[i];
        if (quoted) {
            if (escaped) {
                switch (c) {
                    case 'n': token.push_back('\n'); break;
                    case 'r': token.push_back('\r'); break;
                    case 't': token.push_back('\t'); break;
                    default: token.push_back(c); break;
                }
                escaped = false;
            } else if (quote_char == '"' && c == '\\') {
                escaped = true;
            } else if (c == quote_char) {
                out.push_back(token);
                token.clear();
                quoted = false;
            } else {
                token.push_back(c);
            }
            continue;
        }

        if (c == '"' || c == '\'') {
            quoted = true;
            quote_char = c;
            token.clear();
            unquoted_token = false;
            continue;
        }
        if (c == ',') {
            if (unquoted_token) {
                token = trim(token);
                if (!token.empty()) out.push_back(token);
                token.clear();
                unquoted_token = false;
            }
            continue;
        }
        if (!std::isspace(static_cast<unsigned char>(c))) {
            token.push_back(c);
            unquoted_token = true;
        } else if (unquoted_token) {
            token.push_back(c);
        }
    }

    if (unquoted_token) {
        token = trim(token);
        if (!token.empty()) out.push_back(token);
    }
    return out;
}

bool parseProfileSection(const std::string &section, std::string *profile_name, std::string *bucket) {
    constexpr const char *prefix = "profiles.";
    if (section.rfind(prefix, 0) != 0) return false;
    const std::string rest = section.substr(strlen(prefix));
    const size_t dot = rest.rfind('.');
    if (dot == std::string::npos || dot == 0 || dot + 1 >= rest.size()) return false;
    *profile_name = rest.substr(0, dot);
    *bucket = rest.substr(dot + 1);
    return true;
}

std::string readFdToString(int fd) {
    std::string out;
    char buffer[4096];
    for (;;) {
        ssize_t count = TEMP_FAILURE_RETRY(read(fd, buffer, sizeof(buffer)));
        if (count < 0) {
            out.clear();
            return out;
        }
        if (count == 0) return out;
        out.append(buffer, static_cast<size_t>(count));
    }
}

RuntimeConfig parseConfig(const std::string &content) {
    RuntimeConfig config;
    std::string section;
    AppRule *current_app = nullptr;
    std::string app_list_profile;
    bool app_list_enabled = true;
    std::vector<std::string> app_list_packages;

    auto flushAppList = [&]() {
        for (const std::string &package_name : app_list_packages) {
            if (package_name.empty()) continue;
            AppRule rule;
            rule.package_name = package_name;
            rule.profile_name = app_list_profile;
            rule.enabled = app_list_enabled;
            config.apps.push_back(std::move(rule));
        }
        app_list_packages.clear();
    };

    std::istringstream stream(content);
    std::string raw_line;
    while (std::getline(stream, raw_line)) {
        std::string line = trim(stripComment(raw_line));
        if (line.empty()) continue;

        if (line == "[[apps]]") {
            if (section == "apps" && current_app == nullptr) flushAppList();
            config.apps.emplace_back();
            current_app = &config.apps.back();
            section = "apps";
            continue;
        }

        if (line.size() >= 2 && line.front() == '[' && line.back() == ']') {
            if (section == "apps" && current_app == nullptr) flushAppList();
            section = trim(line.substr(1, line.size() - 2));
            current_app = nullptr;
            if (section == "apps") {
                app_list_profile.clear();
                app_list_enabled = true;
            }
            continue;
        }

        const size_t pos = line.find('=');
        if (pos == std::string::npos) continue;

        const std::string key = trim(line.substr(0, pos));
        std::string raw_value = trim(line.substr(pos + 1));
        if (!raw_value.empty() && raw_value.front() == '[' && !hasArrayEnd(raw_value)) {
            while (std::getline(stream, raw_line)) {
                std::string next = trim(stripComment(raw_line));
                if (next.empty()) continue;
                raw_value += " " + next;
                if (hasArrayEnd(raw_value)) break;
            }
        }
        const std::string value = unquote(raw_value);
        if (key.empty()) continue;

        if (section == "global") {
            if (key == "default_profile") config.default_profile = value;
            if (key == "log") config.log = parseBool(value, config.log);
            if (key == "log_file") config.log_file = parseBool(value, config.log_file);
            if (key == "log_unmatched") config.log_unmatched = parseBool(value, config.log_unmatched);
            if (key == "art_hooks") config.art_hooks = parseBool(value, config.art_hooks);
            if (key == "native_property_hook") config.native_property_hook = parseBool(value, config.native_property_hook);
            if (key == "allow_wildcard_heavy_hooks") {
                config.allow_wildcard_heavy_hooks = parseBool(value, config.allow_wildcard_heavy_hooks);
            }
            if (key == "log_hook_hits") config.log_hook_hits = parseBool(value, config.log_hook_hits);
            if (key == "log_max_bytes") config.log_max_bytes = parseLong(value, config.log_max_bytes);
            continue;
        }

        if (section == "apps" && current_app != nullptr) {
            if (key == "package") current_app->package_name = value;
            if (key == "enabled") current_app->enabled = parseBool(value, current_app->enabled);
            if (key == "profile") current_app->profile_name = value;
            continue;
        }

        if (section == "apps" && current_app == nullptr) {
            if (key == "enabled") app_list_enabled = parseBool(value, app_list_enabled);
            if (key == "profile") app_list_profile = value;
            if (key == "packages") {
                std::vector<std::string> packages = parseStringArray(raw_value);
                app_list_packages.insert(app_list_packages.end(), packages.begin(), packages.end());
            }
            continue;
        }

        std::string profile_name;
        std::string bucket;
        if (parseProfileSection(section, &profile_name, &bucket)) {
            Profile &profile = config.profiles[profile_name];
            if (bucket == "properties") {
                profile.properties[key] = value;
            } else if (bucket == "build") {
                profile.build_fields[key] = value;
            } else if (bucket == "build_version") {
                profile.build_fields["VERSION." + key] = value;
            } else if (bucket == "app_features") {
                profile.app_features[key] = value;
            } else if (bucket == "locale") {
                if (key == "language") profile.locale_language = value;
                if (key == "country") profile.locale_country = value;
            }
        }
    }

    if (section == "apps" && current_app == nullptr) flushAppList();
    return config;
}

RuntimeConfig loadConfigFromModuleDir(int module_dir_fd) {
    if (module_dir_fd < 0) return {};
    const int fd = TEMP_FAILURE_RETRY(openat(module_dir_fd, kConfigPath, O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        LOGW("config open failed: %s", strerror(errno));
        return {};
    }
    std::string content = readFdToString(fd);
    close(fd);
    return parseConfig(content);
}

void openModuleLogFile(int module_dir_fd) {
    if (!g_active.log || !g_active.log_file || g_log_fd != -1) return;

    int fd = -1;
    if (module_dir_fd >= 0) {
        mkdirat(module_dir_fd, kLogDirPath, 0755);
        fd = TEMP_FAILURE_RETRY(openat(
                module_dir_fd,
                kLogFilePath,
                O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                0644));
    }
    if (fd < 0) {
        mkdir("/data/adb/modules/custom_app_spoofer/logs", 0755);
        fd = TEMP_FAILURE_RETRY(open(
                kAbsoluteLogFilePath,
                O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                0644));
    }
    if (fd < 0) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "log file open failed: %s", strerror(errno));
        g_log_fd = -2; // companion-only fallback
        LOGW("log file direct open failed; using companion fallback");
        return;
    }

    struct stat st = {};
    if (g_active.log_max_bytes > 0 && fstat(fd, &st) == 0 && st.st_size > g_active.log_max_bytes) {
        ftruncate(fd, 0);
        lseek(fd, 0, SEEK_SET);
    }

    g_log_fd = fd;
    LOGI("log file ready: %s max_bytes=%ld", kAbsoluteLogFilePath, g_active.log_max_bytes);
}

void closeModuleLogFile() {
    if (g_log_fd >= 0) {
        close(g_log_fd);
    }
    g_log_fd = -1;
}

std::string jstringToString(JNIEnv *env, jstring value) {
    if (value == nullptr) return {};
    const char *chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return {};
    std::string out(chars);
    env->ReleaseStringUTFChars(value, chars);
    return out;
}

jstring newString(JNIEnv *env, const std::string &value) {
    return env->NewStringUTF(value.c_str());
}

std::string packageFromProcessName(std::string process_name) {
    const size_t colon = process_name.find(':');
    if (colon != std::string::npos) process_name.resize(colon);
    return process_name;
}

bool packageMatches(const AppRule &rule, const std::string &package_name, const std::string &process_name) {
    return rule.package_name == "*" ||
           rule.package_name == package_name ||
           rule.package_name == process_name;
}

bool heavyHooksAllowed() {
    return !g_active.matched_wildcard || g_active.allow_wildcard_heavy_hooks;
}

bool hasPropertyOverrides(const Profile &profile) {
    return !profile.properties.empty();
}

bool needsArtHooks(const ActiveConfig &active) {
    return active.enabled &&
           active.art_hooks &&
           (!active.matched_wildcard || active.allow_wildcard_heavy_hooks) &&
           !active.profile.app_features.empty();
}

ActiveConfig selectActiveConfig(const RuntimeConfig &config, const std::string &process_name) {
    ActiveConfig active;
    active.process_name = process_name;
    active.package_name = packageFromProcessName(process_name);
    active.log = config.log;
    active.log_file = config.log_file;
    active.log_unmatched = config.log_unmatched;
    active.art_hooks = config.art_hooks;
    active.native_property_hook = config.native_property_hook;
    active.allow_wildcard_heavy_hooks = config.allow_wildcard_heavy_hooks;
    active.log_hook_hits = config.log_hook_hits;
    active.log_max_bytes = config.log_max_bytes;

    for (const AppRule &rule : config.apps) {
        if (!rule.enabled || rule.package_name.empty()) continue;
        if (!packageMatches(rule, active.package_name, process_name)) continue;

        const std::string profile_name = rule.profile_name.empty() ? config.default_profile : rule.profile_name;
        const auto profile_it = config.profiles.find(profile_name);
        if (profile_it == config.profiles.end()) {
            LOGW("profile not found: %s", profile_name.c_str());
            return active;
        }

        active.enabled = true;
        active.profile_name = profile_name;
        active.profile = profile_it->second;
        active.matched_wildcard = rule.package_name == "*";
        return active;
    }

    return active;
}

std::optional<std::string> findPropertyOverride(const std::string &key) {
    if (!g_active.enabled) return std::nullopt;
    const auto it = g_active.profile.properties.find(key);
    if (it == g_active.profile.properties.end()) return std::nullopt;
    return it->second;
}

std::optional<bool> parseOptionalBool(const std::string &value) {
    const std::string lower = toLower(trim(value));
    if (lower == "true" || lower == "1" || lower == "yes" || lower == "on") return true;
    if (lower == "false" || lower == "0" || lower == "no" || lower == "off") return false;
    return std::nullopt;
}

jstring hookedNativeGet1(JNIEnv *env, jclass clazz, jstring key) {
    const std::string name = jstringToString(env, key);
    if (auto value = findPropertyOverride(name)) {
        return newString(env, *value);
    }
    return g_orig_native_get1 ? g_orig_native_get1(env, clazz, key) : newString(env, "");
}

jstring hookedNativeGet2(JNIEnv *env, jclass clazz, jstring key, jstring def) {
    const std::string name = jstringToString(env, key);
    if (auto value = findPropertyOverride(name)) {
        return newString(env, *value);
    }
    return g_orig_native_get2 ? g_orig_native_get2(env, clazz, key, def) : def;
}

jboolean hookedNativeGetBoolean(JNIEnv *env, jclass clazz, jstring key, jboolean def) {
    const std::string name = jstringToString(env, key);
    if (auto value = findPropertyOverride(name)) {
        if (auto bool_value = parseOptionalBool(*value)) return *bool_value ? JNI_TRUE : JNI_FALSE;
    }
    return g_orig_native_get_boolean ? g_orig_native_get_boolean(env, clazz, key, def) : def;
}

jint hookedNativeGetInt(JNIEnv *env, jclass clazz, jstring key, jint def) {
    const std::string name = jstringToString(env, key);
    if (auto value = findPropertyOverride(name)) {
        char *end = nullptr;
        const long parsed = strtol(value->c_str(), &end, 10);
        if (end != value->c_str() && *end == '\0') return static_cast<jint>(parsed);
    }
    return g_orig_native_get_int ? g_orig_native_get_int(env, clazz, key, def) : def;
}

jlong hookedNativeGetLong(JNIEnv *env, jclass clazz, jstring key, jlong def) {
    const std::string name = jstringToString(env, key);
    if (auto value = findPropertyOverride(name)) {
        char *end = nullptr;
        const long long parsed = strtoll(value->c_str(), &end, 10);
        if (end != value->c_str() && *end == '\0') return static_cast<jlong>(parsed);
    }
    return g_orig_native_get_long ? g_orig_native_get_long(env, clazz, key, def) : def;
}

int hookedSystemPropertyGet(const char *name, char *value) {
    if (name != nullptr) {
        if (auto override = findPropertyOverride(name)) {
            if (value != nullptr) {
                strncpy(value, override->c_str(), PROP_VALUE_MAX - 1);
                value[PROP_VALUE_MAX - 1] = '\0';
            }
            return static_cast<int>(override->size());
        }
    }
    return g_orig_system_property_get ? g_orig_system_property_get(name, value) : 0;
}

dev_t makeDeviceId(unsigned int major_id, unsigned int minor_id) {
#if defined(makedev)
    return makedev(major_id, minor_id);
#else
    return static_cast<dev_t>((major_id << 8u) | minor_id);
#endif
}

bool looksHookablePath(const std::string &path) {
    if (path.empty() || path[0] != '/') return false;
    if (path.find("/memfd:") != std::string::npos) return false;
    return path.find(".so") != std::string::npos ||
           path.find("/app_process") != std::string::npos ||
           path.find("/system/bin/") != std::string::npos;
}

void registerPropertyPltHooks(zygisk::Api *api) {
    FILE *maps = fopen("/proc/self/maps", "re");
    if (maps == nullptr) return;

    std::set<std::string> seen;
    char line[PATH_MAX + 256];
    while (fgets(line, sizeof(line), maps) != nullptr) {
        unsigned long start = 0;
        unsigned long end = 0;
        unsigned long offset = 0;
        unsigned int major_id = 0;
        unsigned int minor_id = 0;
        unsigned long inode = 0;
        char perms[5] = {};
        char path[PATH_MAX] = {};
        const int matched = sscanf(
                line,
                "%lx-%lx %4s %lx %x:%x %lu %s",
                &start,
                &end,
                perms,
                &offset,
                &major_id,
                &minor_id,
                &inode,
                path);
        if (matched < 7 || inode == 0) continue;
        if (perms[0] != 'r' || perms[2] != 'x') continue;
        const std::string path_string = matched >= 8 ? path : "";
        if (!looksHookablePath(path_string)) continue;

        const std::string key = std::to_string(major_id) + ":" + std::to_string(minor_id) + ":" + std::to_string(inode);
        if (!seen.insert(key).second) continue;

        api->pltHookRegister(
                makeDeviceId(major_id, minor_id),
                static_cast<ino_t>(inode),
                "__system_property_get",
                reinterpret_cast<void *>(hookedSystemPropertyGet),
                reinterpret_cast<void **>(&g_orig_system_property_get));
    }
    fclose(maps);

    if (!api->pltHookCommit()) {
        LOGW("PLT property hook commit failed");
    }
}

void installSystemPropertiesHooks(zygisk::Api *api, JNIEnv *env) {
    if (!hasPropertyOverrides(g_active.profile)) return;
    JNINativeMethod methods[] = {
            {"native_get", "(Ljava/lang/String;)Ljava/lang/String;", reinterpret_cast<void *>(hookedNativeGet1)},
            {"native_get", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", reinterpret_cast<void *>(hookedNativeGet2)},
            {"native_get_boolean", "(Ljava/lang/String;Z)Z", reinterpret_cast<void *>(hookedNativeGetBoolean)},
            {"native_get_int", "(Ljava/lang/String;I)I", reinterpret_cast<void *>(hookedNativeGetInt)},
            {"native_get_long", "(Ljava/lang/String;J)J", reinterpret_cast<void *>(hookedNativeGetLong)},
    };
    api->hookJniNativeMethods(env, "android/os/SystemProperties", methods, sizeof(methods) / sizeof(methods[0]));
    g_orig_native_get1 = reinterpret_cast<NativeGet1>(methods[0].fnPtr);
    g_orig_native_get2 = reinterpret_cast<NativeGet2>(methods[1].fnPtr);
    g_orig_native_get_boolean = reinterpret_cast<NativeGetBoolean>(methods[2].fnPtr);
    g_orig_native_get_int = reinterpret_cast<NativeGetInt>(methods[3].fnPtr);
    g_orig_native_get_long = reinterpret_cast<NativeGetLong>(methods[4].fnPtr);
}

void clearPendingException(JNIEnv *env) {
    if (env->ExceptionCheck()) env->ExceptionClear();
}

std::string stripFeatureStringPrefix(const std::string &value) {
    constexpr const char *prefix = "String:";
    if (value.rfind(prefix, 0) == 0) return value.substr(strlen(prefix));
    return value;
}

bool endsWith(const std::string &value, const char *suffix) {
    const size_t suffix_len = strlen(suffix);
    return value.size() >= suffix_len &&
           value.compare(value.size() - suffix_len, suffix_len, suffix) == 0;
}

bool rangeFits(size_t offset, size_t size, size_t total) {
    return offset <= total && size <= total - offset;
}

class ArtElfResolver {
public:
    ~ArtElfResolver() {
        if (mapped_ != nullptr && mapped_ != MAP_FAILED) {
            munmap(mapped_, mapped_size_);
        }
    }

    bool load() {
        if (mapped_ != nullptr && mapped_ != MAP_FAILED) return true;
        if (!findLibArt()) return false;

        const int fd = TEMP_FAILURE_RETRY(open(path_.c_str(), O_RDONLY | O_CLOEXEC));
        if (fd < 0) return false;

        struct stat st = {};
        if (fstat(fd, &st) != 0 || st.st_size <= 0) {
            close(fd);
            return false;
        }

        mapped_size_ = static_cast<size_t>(st.st_size);
        mapped_ = mmap(nullptr, mapped_size_, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        return mapped_ != MAP_FAILED;
    }

    void *resolve(std::string_view symbol) {
        if (!load()) return nullptr;
        if (void *address = dlsym(RTLD_DEFAULT, std::string(symbol).c_str())) return address;
        return resolveFromElf(symbol, false);
    }

    void *resolvePrefix(std::string_view prefix) {
        if (!load()) return nullptr;
        return resolveFromElf(prefix, true);
    }

private:
    bool findLibArt() {
        FILE *maps = fopen("/proc/self/maps", "re");
        if (maps == nullptr) return false;

        char line[PATH_MAX + 256];
        while (fgets(line, sizeof(line), maps) != nullptr) {
            unsigned long start = 0;
            unsigned long end = 0;
            unsigned long offset = 0;
            unsigned int major_id = 0;
            unsigned int minor_id = 0;
            unsigned long inode = 0;
            char perms[5] = {};
            char path[PATH_MAX] = {};
            const int matched = sscanf(
                    line,
                    "%lx-%lx %4s %lx %x:%x %lu %s",
                    &start,
                    &end,
                    perms,
                    &offset,
                    &major_id,
                    &minor_id,
                    &inode,
                    path);
            if (matched < 8 || inode == 0) continue;

            std::string candidate(path);
            if (!endsWith(candidate, "/libart.so")) continue;
            path_ = std::move(candidate);
            base_address_ = static_cast<uintptr_t>(start - offset);
            fclose(maps);
            return true;
        }

        fclose(maps);
        return false;
    }

    void *resolveFromElf(std::string_view query, bool prefix) const {
        if (mapped_ == nullptr || mapped_ == MAP_FAILED || base_address_ == 0) return nullptr;
        const auto *data = static_cast<const unsigned char *>(mapped_);
        if (!rangeFits(0, sizeof(ElfW(Ehdr)), mapped_size_)) return nullptr;

        const auto *ehdr = reinterpret_cast<const ElfW(Ehdr) *>(data);
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return nullptr;
        const size_t sh_size = static_cast<size_t>(ehdr->e_shentsize) * ehdr->e_shnum;
        if (!rangeFits(static_cast<size_t>(ehdr->e_shoff), sh_size, mapped_size_)) return nullptr;

        const auto *sections = reinterpret_cast<const ElfW(Shdr) *>(data + ehdr->e_shoff);
        for (size_t i = 0; i < ehdr->e_shnum; ++i) {
            const ElfW(Shdr) &sym_section = sections[i];
            if (sym_section.sh_type != SHT_SYMTAB && sym_section.sh_type != SHT_DYNSYM) continue;
            if (sym_section.sh_link >= ehdr->e_shnum) continue;
            if (!rangeFits(static_cast<size_t>(sym_section.sh_offset),
                           static_cast<size_t>(sym_section.sh_size),
                           mapped_size_)) {
                continue;
            }

            const ElfW(Shdr) &str_section = sections[sym_section.sh_link];
            if (!rangeFits(static_cast<size_t>(str_section.sh_offset),
                           static_cast<size_t>(str_section.sh_size),
                           mapped_size_)) {
                continue;
            }

            const auto *symbols = reinterpret_cast<const ElfW(Sym) *>(data + sym_section.sh_offset);
            const char *strings = reinterpret_cast<const char *>(data + str_section.sh_offset);
            const size_t symbol_count = sym_section.sh_size / sizeof(ElfW(Sym));
            const size_t string_size = static_cast<size_t>(str_section.sh_size);

            for (size_t n = 0; n < symbol_count; ++n) {
                const ElfW(Sym) &symbol = symbols[n];
                if (symbol.st_name >= string_size || symbol.st_value == 0 || symbol.st_shndx == SHN_UNDEF) {
                    continue;
                }
                const char *name = strings + symbol.st_name;
                const size_t max_len = string_size - symbol.st_name;
                std::string_view symbol_name(name, strnlen(name, max_len));
                const bool match = prefix ? symbol_name.rfind(query, 0) == 0 : symbol_name == query;
                if (match) return reinterpret_cast<void *>(base_address_ + symbol.st_value);
            }
        }

        return nullptr;
    }

    std::string path_;
    uintptr_t base_address_ = 0;
    void *mapped_ = nullptr;
    size_t mapped_size_ = 0;
};

bool makePageWritableExecutable(void *address, size_t size) {
    if (address == nullptr) return false;
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;
    const uintptr_t page_size = static_cast<uintptr_t>(page);
    const uintptr_t start = reinterpret_cast<uintptr_t>(address) & ~(page_size - 1);
    const uintptr_t end = (reinterpret_cast<uintptr_t>(address) + size + page_size - 1) & ~(page_size - 1);
    return mprotect(reinterpret_cast<void *>(start),
                    end > start ? end - start : page_size,
                    PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

void *inlineHooker(void *target, void *hooker) {
    makePageWritableExecutable(target, 16);
    void *origin = nullptr;
    return DobbyHook(target, hooker, &origin) == 0 ? origin : nullptr;
}

bool inlineUnhooker(void *func) {
    return DobbyDestroy(func) == 0;
}

bool ensureLsPlant(JNIEnv *env) {
    if (g_lsplant_attempted) return g_lsplant_initialized;
    g_lsplant_attempted = true;

    static ArtElfResolver resolver;
    g_art_resolver = &resolver;
    if (!g_art_resolver->load()) {
        LOGW("failed to load libart resolver");
        return false;
    }

    lsplant::InitInfo init_info{
            .inline_hooker = inlineHooker,
            .inline_unhooker = inlineUnhooker,
            .art_symbol_resolver = [](std::string_view symbol) -> void * {
                return g_art_resolver ? g_art_resolver->resolve(symbol) : nullptr;
            },
            .art_symbol_prefix_resolver = [](std::string_view prefix) -> void * {
                return g_art_resolver ? g_art_resolver->resolvePrefix(prefix) : nullptr;
            },
            .generated_class_name = "OOSRegionFakerHooker_",
            .generated_source_name = "OOSRegionFaker",
            .generated_field_name = "hooker",
            .generated_method_name = "{target}",
    };
    g_lsplant_initialized = lsplant::Init(env, init_info);
    if (!g_lsplant_initialized) LOGW("LSPlant init failed");
    else if (g_active.log) LOGI("LSPlant init ready");
    clearPendingException(env);
    return g_lsplant_initialized;
}

jobject hookBridgeDispatch(JNIEnv *env, jclass clazz, jint id, jobjectArray args);

jclass findClassNoThrow(JNIEnv *env, const char *name) {
    jclass clazz = env->FindClass(name);
    if (clazz == nullptr) clearPendingException(env);
    return clazz;
}

jobject getContextClassLoader(JNIEnv *env) {
    jclass thread_class = findClassNoThrow(env, "java/lang/Thread");
    if (thread_class == nullptr) return nullptr;

    jmethodID current_thread = env->GetStaticMethodID(thread_class, "currentThread", "()Ljava/lang/Thread;");
    jmethodID get_context_loader = env->GetMethodID(thread_class, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
    if (current_thread == nullptr || get_context_loader == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(thread_class);
        return nullptr;
    }

    jobject thread = env->CallStaticObjectMethod(thread_class, current_thread);
    jobject loader = thread != nullptr ? env->CallObjectMethod(thread, get_context_loader) : nullptr;
    clearPendingException(env);
    if (thread != nullptr) env->DeleteLocalRef(thread);
    env->DeleteLocalRef(thread_class);
    return loader;
}

jobject getSystemClassLoader(JNIEnv *env) {
    jclass loader_class = findClassNoThrow(env, "java/lang/ClassLoader");
    if (loader_class == nullptr) return nullptr;
    jmethodID get_system = env->GetStaticMethodID(
            loader_class,
            "getSystemClassLoader",
            "()Ljava/lang/ClassLoader;");
    if (get_system == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(loader_class);
        return nullptr;
    }
    jobject loader = env->CallStaticObjectMethod(loader_class, get_system);
    clearPendingException(env);
    env->DeleteLocalRef(loader_class);
    return loader;
}

jclass classForName(JNIEnv *env, const std::string &name, jobject loader) {
    jclass class_class = findClassNoThrow(env, "java/lang/Class");
    if (class_class == nullptr) return nullptr;
    jmethodID for_name = env->GetStaticMethodID(
            class_class,
            "forName",
            "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;");
    if (for_name == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(class_class);
        return nullptr;
    }

    jstring j_name = newString(env, name);
    auto clazz = static_cast<jclass>(env->CallStaticObjectMethod(
            class_class,
            for_name,
            j_name,
            JNI_FALSE,
            loader));
    clearPendingException(env);
    env->DeleteLocalRef(j_name);
    env->DeleteLocalRef(class_class);
    return clazz;
}

jclass findRuntimeClass(JNIEnv *env, const std::string &name) {
    jobject context_loader = getContextClassLoader(env);
    if (jclass clazz = classForName(env, name, context_loader)) {
        if (context_loader != nullptr) env->DeleteLocalRef(context_loader);
        return clazz;
    }

    jobject system_loader = getSystemClassLoader(env);
    if (jclass clazz = classForName(env, name, system_loader)) {
        if (context_loader != nullptr) env->DeleteLocalRef(context_loader);
        if (system_loader != nullptr) env->DeleteLocalRef(system_loader);
        return clazz;
    }

    jclass clazz = classForName(env, name, nullptr);
    if (context_loader != nullptr) env->DeleteLocalRef(context_loader);
    if (system_loader != nullptr) env->DeleteLocalRef(system_loader);
    return clazz;
}

bool loadHookBridgeDex(JNIEnv *env, int module_dir_fd) {
    if (g_hook_bridge_ready) return true;
    if (module_dir_fd < 0) return false;

    const int fd = TEMP_FAILURE_RETRY(openat(module_dir_fd, kHookerDexPath, O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        LOGW("hooker dex open failed: %s", strerror(errno));
        return false;
    }
    std::string dex = readFdToString(fd);
    close(fd);
    if (dex.empty()) {
        LOGW("hooker dex is empty");
        return false;
    }

    jbyteArray dex_array = env->NewByteArray(static_cast<jsize>(dex.size()));
    if (dex_array == nullptr) {
        clearPendingException(env);
        return false;
    }
    env->SetByteArrayRegion(
            dex_array,
            0,
            static_cast<jsize>(dex.size()),
            reinterpret_cast<const jbyte *>(dex.data()));

    jclass byte_buffer_class = findClassNoThrow(env, "java/nio/ByteBuffer");
    jclass dex_loader_class = findClassNoThrow(env, "dalvik/system/InMemoryDexClassLoader");
    jclass class_loader_class = findClassNoThrow(env, "java/lang/ClassLoader");
    if (byte_buffer_class == nullptr || dex_loader_class == nullptr || class_loader_class == nullptr) {
        if (byte_buffer_class != nullptr) env->DeleteLocalRef(byte_buffer_class);
        if (dex_loader_class != nullptr) env->DeleteLocalRef(dex_loader_class);
        if (class_loader_class != nullptr) env->DeleteLocalRef(class_loader_class);
        env->DeleteLocalRef(dex_array);
        return false;
    }

    jmethodID wrap = env->GetStaticMethodID(byte_buffer_class, "wrap", "([B)Ljava/nio/ByteBuffer;");
    jmethodID loader_ctor = env->GetMethodID(
            dex_loader_class,
            "<init>",
            "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jmethodID load_class = env->GetMethodID(
            class_loader_class,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;");
    if (wrap == nullptr || loader_ctor == nullptr || load_class == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(byte_buffer_class);
        env->DeleteLocalRef(dex_loader_class);
        env->DeleteLocalRef(class_loader_class);
        env->DeleteLocalRef(dex_array);
        return false;
    }

    jobject buffer = env->CallStaticObjectMethod(byte_buffer_class, wrap, dex_array);
    jobject parent_loader = getContextClassLoader(env);
    if (parent_loader == nullptr) parent_loader = getSystemClassLoader(env);
    jobject dex_loader = buffer != nullptr ? env->NewObject(dex_loader_class, loader_ctor, buffer, parent_loader) : nullptr;
    jstring bridge_name = newString(env, "dev.mi.appspoof.HookBridge");
    jobject bridge_class_obj = dex_loader != nullptr
                               ? env->CallObjectMethod(dex_loader, load_class, bridge_name)
                               : nullptr;
    clearPendingException(env);

    if (bridge_class_obj != nullptr) {
        auto bridge_class = static_cast<jclass>(bridge_class_obj);
        g_hook_bridge_class = static_cast<jclass>(env->NewGlobalRef(bridge_class));
        JNINativeMethod native_method = {
                const_cast<char *>("dispatch"),
                const_cast<char *>("(I[Ljava/lang/Object;)Ljava/lang/Object;"),
                reinterpret_cast<void *>(hookBridgeDispatch),
        };
        if (env->RegisterNatives(g_hook_bridge_class, &native_method, 1) != 0) {
            clearPendingException(env);
        } else {
            g_hook_bridge_ctor = env->GetMethodID(g_hook_bridge_class, "<init>", "(I)V");
            jmethodID callback = env->GetMethodID(
                    g_hook_bridge_class,
                    "callback",
                    "([Ljava/lang/Object;)Ljava/lang/Object;");
            jobject callback_method = callback != nullptr
                                      ? env->ToReflectedMethod(g_hook_bridge_class, callback, JNI_FALSE)
                                      : nullptr;
            if (g_hook_bridge_ctor != nullptr && callback_method != nullptr) {
                g_hook_bridge_callback_method = env->NewGlobalRef(callback_method);
                g_hook_bridge_ready = g_hook_bridge_callback_method != nullptr;
            }
            clearPendingException(env);
            if (callback_method != nullptr) env->DeleteLocalRef(callback_method);
        }
    }

    if (!g_hook_bridge_ready) LOGW("hook bridge init failed");
    else if (g_active.log) LOGI("hook bridge ready");
    if (bridge_class_obj != nullptr) env->DeleteLocalRef(bridge_class_obj);
    env->DeleteLocalRef(bridge_name);
    if (dex_loader != nullptr) env->DeleteLocalRef(dex_loader);
    if (parent_loader != nullptr) env->DeleteLocalRef(parent_loader);
    if (buffer != nullptr) env->DeleteLocalRef(buffer);
    env->DeleteLocalRef(byte_buffer_class);
    env->DeleteLocalRef(dex_loader_class);
    env->DeleteLocalRef(class_loader_class);
    env->DeleteLocalRef(dex_array);
    return g_hook_bridge_ready;
}

std::string classObjectName(JNIEnv *env, jobject class_object) {
    if (class_object == nullptr) return {};
    jclass class_class = findClassNoThrow(env, "java/lang/Class");
    if (class_class == nullptr) return {};
    jmethodID get_name = env->GetMethodID(class_class, "getName", "()Ljava/lang/String;");
    if (get_name == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(class_class);
        return {};
    }
    auto name = static_cast<jstring>(env->CallObjectMethod(class_object, get_name));
    std::string out = jstringToString(env, name);
    clearPendingException(env);
    if (name != nullptr) env->DeleteLocalRef(name);
    env->DeleteLocalRef(class_class);
    return out;
}

struct ReflectedMethodInfo {
    std::string name;
    std::string return_type;
    std::vector<std::string> parameter_types;
    bool is_static = false;
};

bool readReflectedMethodInfo(JNIEnv *env, jobject method, ReflectedMethodInfo *info) {
    jclass method_class = findClassNoThrow(env, "java/lang/reflect/Method");
    if (method_class == nullptr) return false;

    jmethodID get_name = env->GetMethodID(method_class, "getName", "()Ljava/lang/String;");
    jmethodID get_return_type = env->GetMethodID(method_class, "getReturnType", "()Ljava/lang/Class;");
    jmethodID get_parameter_types = env->GetMethodID(method_class, "getParameterTypes", "()[Ljava/lang/Class;");
    jmethodID get_modifiers = env->GetMethodID(method_class, "getModifiers", "()I");
    if (get_name == nullptr || get_return_type == nullptr || get_parameter_types == nullptr || get_modifiers == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(method_class);
        return false;
    }

    auto name = static_cast<jstring>(env->CallObjectMethod(method, get_name));
    jobject return_type = env->CallObjectMethod(method, get_return_type);
    auto params = static_cast<jobjectArray>(env->CallObjectMethod(method, get_parameter_types));
    const jint modifiers = env->CallIntMethod(method, get_modifiers);
    if (env->ExceptionCheck()) {
        clearPendingException(env);
        if (name != nullptr) env->DeleteLocalRef(name);
        if (return_type != nullptr) env->DeleteLocalRef(return_type);
        if (params != nullptr) env->DeleteLocalRef(params);
        env->DeleteLocalRef(method_class);
        return false;
    }

    info->name = jstringToString(env, name);
    info->return_type = classObjectName(env, return_type);
    info->is_static = (modifiers & 0x0008) != 0;

    if (params != nullptr) {
        const jsize count = env->GetArrayLength(params);
        info->parameter_types.reserve(static_cast<size_t>(count));
        for (jsize i = 0; i < count; ++i) {
            jobject param = env->GetObjectArrayElement(params, i);
            info->parameter_types.push_back(classObjectName(env, param));
            if (param != nullptr) env->DeleteLocalRef(param);
        }
    }

    if (name != nullptr) env->DeleteLocalRef(name);
    if (return_type != nullptr) env->DeleteLocalRef(return_type);
    if (params != nullptr) env->DeleteLocalRef(params);
    env->DeleteLocalRef(method_class);
    return !info->name.empty() && !info->return_type.empty();
}

bool methodHasStringParameter(const ReflectedMethodInfo &info) {
    return std::find(info.parameter_types.begin(), info.parameter_types.end(), "java.lang.String") !=
           info.parameter_types.end();
}

bool shouldHookAppFeatureMethod(const ReflectedMethodInfo &info) {
    if (!methodHasStringParameter(info)) return false;
    return info.return_type == "boolean" ||
           info.return_type == "java.lang.Boolean" ||
           info.return_type == "java.lang.String" ||
           info.return_type == "java.lang.Object";
}

bool shouldHookContentResolverQuery(const ReflectedMethodInfo &info) {
    return info.name == "query" &&
           info.return_type == "android.database.Cursor" &&
           !info.parameter_types.empty() &&
           info.parameter_types.front() == "android.net.Uri";
}

bool setMethodAccessible(JNIEnv *env, jobject method) {
    jclass method_class = findClassNoThrow(env, "java/lang/reflect/Method");
    if (method_class == nullptr) return false;
    jmethodID set_accessible = env->GetMethodID(method_class, "setAccessible", "(Z)V");
    if (set_accessible != nullptr) {
        env->CallVoidMethod(method, set_accessible, JNI_TRUE);
        clearPendingException(env);
    } else {
        clearPendingException(env);
    }
    env->DeleteLocalRef(method_class);
    return true;
}

bool hookReflectedMethod(JNIEnv *env,
                         jobject method,
                         HookKind kind,
                         const ReflectedMethodInfo &info) {
    if (!g_hook_bridge_ready || !g_lsplant_initialized || method == nullptr) return false;

    const int id = static_cast<int>(g_method_hooks.size()) + 1;
    jobject hooker = env->NewObject(g_hook_bridge_class, g_hook_bridge_ctor, id);
    if (hooker == nullptr) {
        clearPendingException(env);
        return false;
    }

    setMethodAccessible(env, method);
    jobject backup = lsplant::Hook(env, method, hooker, g_hook_bridge_callback_method);
    clearPendingException(env);
    env->DeleteLocalRef(hooker);
    if (backup == nullptr) return false;

    MethodHookRecord record;
    record.id = id;
    record.kind = kind;
    record.backup_method = backup;
    record.is_static = info.is_static;
    record.return_type = info.return_type;
    g_method_hooks.push_back(std::move(record));
    return true;
}

int installHooksInClass(JNIEnv *env,
                        const std::string &class_name,
                        HookKind kind,
                        const std::function<bool(const ReflectedMethodInfo &)> &predicate) {
    jclass target_class = findRuntimeClass(env, class_name);
    if (target_class == nullptr) return 0;

    jclass class_class = findClassNoThrow(env, "java/lang/Class");
    if (class_class == nullptr) {
        env->DeleteLocalRef(target_class);
        return 0;
    }
    jmethodID get_declared_methods = env->GetMethodID(
            class_class,
            "getDeclaredMethods",
            "()[Ljava/lang/reflect/Method;");
    if (get_declared_methods == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(class_class);
        env->DeleteLocalRef(target_class);
        return 0;
    }

    auto methods = static_cast<jobjectArray>(env->CallObjectMethod(target_class, get_declared_methods));
    if (methods == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(class_class);
        env->DeleteLocalRef(target_class);
        return 0;
    }

    int hooked = 0;
    const jsize count = env->GetArrayLength(methods);
    for (jsize i = 0; i < count; ++i) {
        jobject method = env->GetObjectArrayElement(methods, i);
        ReflectedMethodInfo info;
        if (readReflectedMethodInfo(env, method, &info) && predicate(info)) {
            if (hookReflectedMethod(env, method, kind, info)) ++hooked;
        }
        if (method != nullptr) env->DeleteLocalRef(method);
    }

    env->DeleteLocalRef(methods);
    env->DeleteLocalRef(class_class);
    env->DeleteLocalRef(target_class);
    if (hooked > 0 && g_active.log) LOGI("hooked class=%s methods=%d", class_name.c_str(), hooked);
    return hooked;
}

void installArtHooks(JNIEnv *env) {
    if (g_art_hooks_installed || g_active.profile.app_features.empty()) return;
    if (!g_active.art_hooks) return;
    if (!heavyHooksAllowed()) {
        if (g_active.log) LOGW("skip ART hooks for wildcard scope; set allow_wildcard_heavy_hooks=true to force");
        return;
    }
    if (!g_hook_bridge_ready || !ensureLsPlant(env)) return;

    int hooked = 0;
    hooked += installHooksInClass(
            env,
            "android.content.ContentResolver",
            HookKind::ContentResolverQuery,
            shouldHookContentResolverQuery);
    hooked += installHooksInClass(
            env,
            "com.android.common.util.AppFeatureUtils",
            HookKind::AppFeatureMethod,
            shouldHookAppFeatureMethod);
    hooked += installHooksInClass(
            env,
            "com.oplus.coreapp.appfeature.AppFeatureProviderUtils",
            HookKind::AppFeatureMethod,
            shouldHookAppFeatureMethod);

    if (hooked > 0) {
        g_art_hooks_installed = true;
        if (g_active.log) LOGI("installed %d ART hooks", hooked);
    } else if (g_active.log) {
        LOGW("no ART hooks installed");
    }
}

MethodHookRecord *findHookRecord(jint id) {
    if (id <= 0 || static_cast<size_t>(id) > g_method_hooks.size()) return nullptr;
    MethodHookRecord &record = g_method_hooks[static_cast<size_t>(id) - 1];
    return record.id == id ? &record : nullptr;
}

jobject callOriginal(JNIEnv *env, const MethodHookRecord &record, jobjectArray args) {
    if (record.backup_method == nullptr) return nullptr;

    jclass method_class = findClassNoThrow(env, "java/lang/reflect/Method");
    jclass object_class = findClassNoThrow(env, "java/lang/Object");
    if (method_class == nullptr || object_class == nullptr) {
        if (method_class != nullptr) env->DeleteLocalRef(method_class);
        if (object_class != nullptr) env->DeleteLocalRef(object_class);
        return nullptr;
    }

    jmethodID invoke = env->GetMethodID(
            method_class,
            "invoke",
            "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    if (invoke == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(method_class);
        env->DeleteLocalRef(object_class);
        return nullptr;
    }

    const jsize length = args != nullptr ? env->GetArrayLength(args) : 0;
    const jsize first_param = record.is_static ? 0 : 1;
    jobject receiver = nullptr;
    if (!record.is_static && length > 0) receiver = env->GetObjectArrayElement(args, 0);
    const jsize param_count = length > first_param ? length - first_param : 0;
    jobjectArray params = env->NewObjectArray(param_count, object_class, nullptr);
    if (params != nullptr) {
        for (jsize i = 0; i < param_count; ++i) {
            jobject value = env->GetObjectArrayElement(args, first_param + i);
            env->SetObjectArrayElement(params, i, value);
            if (value != nullptr) env->DeleteLocalRef(value);
        }
    }

    jobject result = params != nullptr
                     ? env->CallObjectMethod(record.backup_method, invoke, receiver, params)
                     : nullptr;
    if (receiver != nullptr) env->DeleteLocalRef(receiver);
    if (params != nullptr) env->DeleteLocalRef(params);
    env->DeleteLocalRef(method_class);
    env->DeleteLocalRef(object_class);
    return result;
}

jobject newBooleanObject(JNIEnv *env, bool value) {
    jclass boolean_class = findClassNoThrow(env, "java/lang/Boolean");
    if (boolean_class == nullptr) return nullptr;
    jmethodID value_of = env->GetStaticMethodID(boolean_class, "valueOf", "(Z)Ljava/lang/Boolean;");
    jobject result = value_of != nullptr
                     ? env->CallStaticObjectMethod(boolean_class, value_of, value ? JNI_TRUE : JNI_FALSE)
                     : nullptr;
    clearPendingException(env);
    env->DeleteLocalRef(boolean_class);
    return result;
}

jobject newLongObject(JNIEnv *env, jlong value) {
    jclass long_class = findClassNoThrow(env, "java/lang/Long");
    if (long_class == nullptr) return nullptr;
    jmethodID value_of = env->GetStaticMethodID(long_class, "valueOf", "(J)Ljava/lang/Long;");
    jobject result = value_of != nullptr ? env->CallStaticObjectMethod(long_class, value_of, value) : nullptr;
    clearPendingException(env);
    env->DeleteLocalRef(long_class);
    return result;
}

bool isInstance(JNIEnv *env, jobject value, const char *class_name) {
    if (value == nullptr) return false;
    jclass clazz = findClassNoThrow(env, class_name);
    if (clazz == nullptr) return false;
    const bool result = env->IsInstanceOf(value, clazz) == JNI_TRUE;
    env->DeleteLocalRef(clazz);
    return result;
}

std::string objectToString(JNIEnv *env, jobject value) {
    if (value == nullptr) return {};
    jclass object_class = findClassNoThrow(env, "java/lang/Object");
    if (object_class == nullptr) return {};
    jmethodID to_string = env->GetMethodID(object_class, "toString", "()Ljava/lang/String;");
    if (to_string == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(object_class);
        return {};
    }
    auto text = static_cast<jstring>(env->CallObjectMethod(value, to_string));
    std::string out = jstringToString(env, text);
    clearPendingException(env);
    if (text != nullptr) env->DeleteLocalRef(text);
    env->DeleteLocalRef(object_class);
    return out;
}

std::optional<std::string> findFeatureNameInText(const std::string &text) {
    if (text.empty()) return std::nullopt;
    for (const auto &[feature, value] : g_active.profile.app_features) {
        if (text == feature || text.find(feature) != std::string::npos) return feature;
    }
    return std::nullopt;
}

std::optional<std::string> findFeatureNameInStringArray(JNIEnv *env, jobjectArray array) {
    if (array == nullptr) return std::nullopt;
    const jsize length = env->GetArrayLength(array);
    for (jsize i = 0; i < length; ++i) {
        auto item = static_cast<jstring>(env->GetObjectArrayElement(array, i));
        std::optional<std::string> found = item != nullptr ? findFeatureNameInText(jstringToString(env, item)) : std::nullopt;
        if (item != nullptr) env->DeleteLocalRef(item);
        if (found) return found;
    }
    return std::nullopt;
}

std::optional<std::string> findFeatureNameInArgs(JNIEnv *env, jobjectArray args) {
    if (args == nullptr) return std::nullopt;
    jclass string_array_class = findClassNoThrow(env, "[Ljava/lang/String;");
    const jsize length = env->GetArrayLength(args);
    for (jsize i = 0; i < length; ++i) {
        jobject value = env->GetObjectArrayElement(args, i);
        std::optional<std::string> found;
        if (value != nullptr) {
            if (isInstance(env, value, "java/lang/String")) {
                found = findFeatureNameInText(jstringToString(env, static_cast<jstring>(value)));
            } else if (string_array_class != nullptr && env->IsInstanceOf(value, string_array_class) == JNI_TRUE) {
                found = findFeatureNameInStringArray(env, static_cast<jobjectArray>(value));
            }
            if (!found) found = findFeatureNameInText(objectToString(env, value));
        }
        if (value != nullptr) env->DeleteLocalRef(value);
        if (found) {
            if (string_array_class != nullptr) env->DeleteLocalRef(string_array_class);
            return found;
        }
    }
    if (string_array_class != nullptr) env->DeleteLocalRef(string_array_class);
    return std::nullopt;
}

jobject coerceFeatureReturn(JNIEnv *env, const MethodHookRecord &record, const std::string &raw_value) {
    if (record.return_type == "boolean" || record.return_type == "java.lang.Boolean") {
        if (auto bool_value = parseOptionalBool(raw_value)) return newBooleanObject(env, *bool_value);
        return nullptr;
    }

    const std::string payload = stripFeatureStringPrefix(raw_value);
    if (record.return_type == "java.lang.String") return newString(env, payload);
    if (record.return_type == "java.lang.Object") {
        if (auto bool_value = parseOptionalBool(raw_value)) return newBooleanObject(env, *bool_value);
        return newString(env, payload);
    }
    return nullptr;
}

std::string uriAuthority(JNIEnv *env, jobject uri) {
    if (uri == nullptr || !isInstance(env, uri, "android/net/Uri")) return {};
    jclass uri_class = findClassNoThrow(env, "android/net/Uri");
    if (uri_class == nullptr) return {};
    jmethodID get_authority = env->GetMethodID(uri_class, "getAuthority", "()Ljava/lang/String;");
    if (get_authority == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(uri_class);
        return {};
    }
    auto authority = static_cast<jstring>(env->CallObjectMethod(uri, get_authority));
    std::string out = jstringToString(env, authority);
    clearPendingException(env);
    if (authority != nullptr) env->DeleteLocalRef(authority);
    env->DeleteLocalRef(uri_class);
    return out;
}

std::vector<std::string> defaultFeatureCursorColumns() {
    return {"_id", "featurename", "parameters", "lists"};
}

std::vector<std::string> stringArrayValues(JNIEnv *env, jobjectArray array) {
    if (array == nullptr) return defaultFeatureCursorColumns();
    std::vector<std::string> values;
    const jsize length = env->GetArrayLength(array);
    values.reserve(static_cast<size_t>(length));
    for (jsize i = 0; i < length; ++i) {
        auto item = static_cast<jstring>(env->GetObjectArrayElement(array, i));
        values.push_back(jstringToString(env, item));
        if (item != nullptr) env->DeleteLocalRef(item);
    }
    return values.empty() ? defaultFeatureCursorColumns() : values;
}

std::vector<std::string> queryProjectionColumns(JNIEnv *env,
                                                const MethodHookRecord &record,
                                                jobjectArray args) {
    if (args == nullptr) return defaultFeatureCursorColumns();
    const jsize projection_index = record.is_static ? 1 : 2;
    if (projection_index >= env->GetArrayLength(args)) return defaultFeatureCursorColumns();
    jobject projection = env->GetObjectArrayElement(args, projection_index);
    if (projection == nullptr) return defaultFeatureCursorColumns();

    std::vector<std::string> columns;
    if (isInstance(env, projection, "[Ljava/lang/String;")) {
        columns = stringArrayValues(env, static_cast<jobjectArray>(projection));
    } else {
        columns = defaultFeatureCursorColumns();
    }
    env->DeleteLocalRef(projection);
    return columns;
}

std::string featureColumnValue(const std::string &column,
                               const std::string &feature,
                               const std::string &raw_value) {
    if (column == "featurename" || column == "featureName" || column == "feature_name") return feature;
    if (column == "parameters" || column == "lists") {
        return raw_value.rfind("String:", 0) == 0 ? stripFeatureStringPrefix(raw_value) : "";
    }
    if (column == "enabled" || column == "support" || column == "supported") {
        if (auto bool_value = parseOptionalBool(raw_value)) return *bool_value ? "1" : "0";
    }
    return stripFeatureStringPrefix(raw_value);
}

jobject makeFeatureCursor(JNIEnv *env,
                          const std::vector<std::string> &columns,
                          const std::string &feature,
                          const std::string &raw_value,
                          bool include_row) {
    jclass string_class = findClassNoThrow(env, "java/lang/String");
    jclass object_class = findClassNoThrow(env, "java/lang/Object");
    jclass cursor_class = findClassNoThrow(env, "android/database/MatrixCursor");
    if (string_class == nullptr || object_class == nullptr || cursor_class == nullptr) {
        if (string_class != nullptr) env->DeleteLocalRef(string_class);
        if (object_class != nullptr) env->DeleteLocalRef(object_class);
        if (cursor_class != nullptr) env->DeleteLocalRef(cursor_class);
        return nullptr;
    }

    jobjectArray column_array = env->NewObjectArray(static_cast<jsize>(columns.size()), string_class, nullptr);
    for (jsize i = 0; i < static_cast<jsize>(columns.size()); ++i) {
        jstring column = newString(env, columns[static_cast<size_t>(i)]);
        env->SetObjectArrayElement(column_array, i, column);
        env->DeleteLocalRef(column);
    }

    jmethodID ctor = env->GetMethodID(cursor_class, "<init>", "([Ljava/lang/String;)V");
    jobject cursor = ctor != nullptr ? env->NewObject(cursor_class, ctor, column_array) : nullptr;
    if (cursor != nullptr && include_row) {
        jmethodID add_row = env->GetMethodID(cursor_class, "addRow", "([Ljava/lang/Object;)V");
        jobjectArray row = env->NewObjectArray(static_cast<jsize>(columns.size()), object_class, nullptr);
        for (jsize i = 0; i < static_cast<jsize>(columns.size()); ++i) {
            const std::string &column = columns[static_cast<size_t>(i)];
            jobject cell = column == "_id"
                           ? newLongObject(env, 0)
                           : static_cast<jobject>(newString(env, featureColumnValue(column, feature, raw_value)));
            env->SetObjectArrayElement(row, i, cell);
            if (cell != nullptr) env->DeleteLocalRef(cell);
        }
        if (add_row != nullptr) env->CallVoidMethod(cursor, add_row, row);
        clearPendingException(env);
        env->DeleteLocalRef(row);
    }

    clearPendingException(env);
    env->DeleteLocalRef(column_array);
    env->DeleteLocalRef(string_class);
    env->DeleteLocalRef(object_class);
    env->DeleteLocalRef(cursor_class);
    return cursor;
}

jobject dispatchAppFeatureMethod(JNIEnv *env, const MethodHookRecord &record, jobjectArray args) {
    if (auto feature = findFeatureNameInArgs(env, args)) {
        const auto value_it = g_active.profile.app_features.find(*feature);
        if (value_it != g_active.profile.app_features.end()) {
            if (jobject result = coerceFeatureReturn(env, record, value_it->second)) {
                if (g_active.log && g_active.log_hook_hits) {
                    LOGI("AppFeature method hit feature=%s value=%s return_type=%s",
                         feature->c_str(),
                         value_it->second.c_str(),
                         record.return_type.c_str());
                }
                return result;
            }
        }
    }
    return callOriginal(env, record, args);
}

jobject dispatchContentResolverQuery(JNIEnv *env, const MethodHookRecord &record, jobjectArray args) {
    const jsize uri_index = record.is_static ? 0 : 1;
    if (args == nullptr || uri_index >= env->GetArrayLength(args)) return callOriginal(env, record, args);

    jobject uri = env->GetObjectArrayElement(args, uri_index);
    const std::string authority = uriAuthority(env, uri);
    if (uri != nullptr) env->DeleteLocalRef(uri);
    if (authority != kAppFeatureProviderAuthority) return callOriginal(env, record, args);

    auto feature = findFeatureNameInArgs(env, args);
    if (!feature) return callOriginal(env, record, args);

    const auto value_it = g_active.profile.app_features.find(*feature);
    if (value_it == g_active.profile.app_features.end()) return callOriginal(env, record, args);

    const std::string &raw_value = value_it->second;
    const bool include_row = !parseOptionalBool(raw_value).has_value() || parseOptionalBool(raw_value).value();
    std::vector<std::string> columns = queryProjectionColumns(env, record, args);
    jobject cursor = makeFeatureCursor(env, columns, *feature, raw_value, include_row);
    if (cursor == nullptr) return callOriginal(env, record, args);
    if (g_active.log && g_active.log_hook_hits) {
        LOGI("AppFeature provider hit feature=%s value=%s rows=%d columns=%zu",
             feature->c_str(),
             raw_value.c_str(),
             include_row ? 1 : 0,
             columns.size());
    }
    return cursor;
}

jobject hookBridgeDispatch(JNIEnv *env, jclass clazz, jint id, jobjectArray args) {
    MethodHookRecord *record = findHookRecord(id);
    if (record == nullptr || !g_active.enabled) return nullptr;

    switch (record->kind) {
        case HookKind::AppFeatureMethod:
            return dispatchAppFeatureMethod(env, *record, args);
        case HookKind::ContentResolverQuery:
            return dispatchContentResolverQuery(env, *record, args);
    }
    return callOriginal(env, *record, args);
}

bool setStaticField(JNIEnv *env, jclass clazz, const std::string &field_name, const std::string &value) {
    jfieldID string_field = env->GetStaticFieldID(clazz, field_name.c_str(), "Ljava/lang/String;");
    if (string_field != nullptr) {
        jstring j_value = newString(env, value);
        env->SetStaticObjectField(clazz, string_field, j_value);
        clearPendingException(env);
        env->DeleteLocalRef(j_value);
        return true;
    }
    clearPendingException(env);

    jfieldID int_field = env->GetStaticFieldID(clazz, field_name.c_str(), "I");
    if (int_field != nullptr) {
        char *end = nullptr;
        const long parsed = strtol(value.c_str(), &end, 10);
        if (end != value.c_str() && *end == '\0') {
            env->SetStaticIntField(clazz, int_field, static_cast<jint>(parsed));
            clearPendingException(env);
            return true;
        }
    }
    clearPendingException(env);

    jfieldID long_field = env->GetStaticFieldID(clazz, field_name.c_str(), "J");
    if (long_field != nullptr) {
        char *end = nullptr;
        const long long parsed = strtoll(value.c_str(), &end, 10);
        if (end != value.c_str() && *end == '\0') {
            env->SetStaticLongField(clazz, long_field, static_cast<jlong>(parsed));
            clearPendingException(env);
            return true;
        }
    }
    clearPendingException(env);

    jfieldID bool_field = env->GetStaticFieldID(clazz, field_name.c_str(), "Z");
    if (bool_field != nullptr) {
        if (auto parsed = parseOptionalBool(value)) {
            env->SetStaticBooleanField(clazz, bool_field, *parsed ? JNI_TRUE : JNI_FALSE);
            clearPendingException(env);
            return true;
        }
    }
    clearPendingException(env);
    return false;
}

bool splitBuildTarget(const std::string &key, std::string *class_name, std::string *field_name) {
    *class_name = "android/os/Build";
    *field_name = key;

    constexpr const char *build_prefix = "Build.";
    constexpr const char *version_prefix = "VERSION.";
    constexpr const char *build_version_prefix = "Build.VERSION.";
    if (key.rfind(build_version_prefix, 0) == 0) {
        *class_name = "android/os/Build$VERSION";
        *field_name = key.substr(strlen(build_version_prefix));
    } else if (key.rfind(version_prefix, 0) == 0) {
        *class_name = "android/os/Build$VERSION";
        *field_name = key.substr(strlen(version_prefix));
    } else if (key.rfind(build_prefix, 0) == 0) {
        *field_name = key.substr(strlen(build_prefix));
    }
    return !field_name->empty();
}

void applyJavaSystemProperties(JNIEnv *env) {
    if (g_active.profile.properties.empty()) return;
    jclass system_class = env->FindClass("java/lang/System");
    if (system_class == nullptr) {
        clearPendingException(env);
        return;
    }
    jmethodID set_property = env->GetStaticMethodID(
            system_class,
            "setProperty",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if (set_property == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(system_class);
        return;
    }

    for (const auto &[key, value] : g_active.profile.properties) {
        jstring j_key = newString(env, key);
        jstring j_value = newString(env, value);
        jobject old_value = env->CallStaticObjectMethod(system_class, set_property, j_key, j_value);
        clearPendingException(env);
        if (old_value != nullptr) env->DeleteLocalRef(old_value);
        env->DeleteLocalRef(j_key);
        env->DeleteLocalRef(j_value);
    }
    env->DeleteLocalRef(system_class);
}

void applyBuildFields(JNIEnv *env) {
    if (g_active.profile.build_fields.empty()) return;

    for (const auto &[field_name, value] : g_active.profile.build_fields) {
        std::string class_name;
        std::string target_field;
        if (!splitBuildTarget(field_name, &class_name, &target_field)) continue;

        jclass build_class = env->FindClass(class_name.c_str());
        if (build_class == nullptr) {
            clearPendingException(env);
            continue;
        }
        if (!setStaticField(env, build_class, target_field, value) && g_active.log) {
            LOGW("Build field not found or unsupported: %s.%s", class_name.c_str(), target_field.c_str());
        }
        env->DeleteLocalRef(build_class);
    }
}

void applyLocale(JNIEnv *env) {
    const std::string &language = g_active.profile.locale_language;
    const std::string &country = g_active.profile.locale_country;
    if (language.empty() && country.empty()) return;

    jclass locale_class = env->FindClass("java/util/Locale");
    if (locale_class == nullptr) {
        clearPendingException(env);
        return;
    }

    jmethodID constructor = env->GetMethodID(
            locale_class,
            "<init>",
            "(Ljava/lang/String;Ljava/lang/String;)V");
    jmethodID set_default = env->GetStaticMethodID(
            locale_class,
            "setDefault",
            "(Ljava/util/Locale;)V");
    if (constructor == nullptr || set_default == nullptr) {
        clearPendingException(env);
        env->DeleteLocalRef(locale_class);
        return;
    }

    jstring j_language = newString(env, language.empty() ? "zh" : language);
    jstring j_country = newString(env, country.empty() ? "CN" : country);
    jobject locale = env->NewObject(locale_class, constructor, j_language, j_country);
    if (locale != nullptr) {
        env->CallStaticVoidMethod(locale_class, set_default, locale);
        clearPendingException(env);
        env->DeleteLocalRef(locale);
    }
    env->DeleteLocalRef(j_language);
    env->DeleteLocalRef(j_country);
    env->DeleteLocalRef(locale_class);
}

class OOSRegionFaker : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        api_ = api;
        env_ = env;
        g_api = api;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        g_active = {};
        const std::string process_name = jstringToString(env_, args->nice_name);
        if (process_name.empty()) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        const int module_dir = api_->getModuleDir();
        RuntimeConfig config = loadConfigFromModuleDir(module_dir);

        g_active.process_name = process_name;
        g_active.package_name = packageFromProcessName(process_name);
        g_active.log = config.log;
        g_active.log_file = config.log_file;
        g_active.log_unmatched = config.log_unmatched;
        g_active.art_hooks = config.art_hooks;
        g_active.native_property_hook = config.native_property_hook;
        g_active.allow_wildcard_heavy_hooks = config.allow_wildcard_heavy_hooks;
        g_active.log_hook_hits = config.log_hook_hits;
        g_active.log_max_bytes = config.log_max_bytes;
        if (g_active.log && g_active.log_unmatched) {
            openModuleLogFile(module_dir);
            LOGI("zygisk entry package=%s process=%s rules=%zu profiles=%zu",
                 g_active.package_name.c_str(),
                 g_active.process_name.c_str(),
                 config.apps.size(),
                 config.profiles.size());
        }

        g_active = selectActiveConfig(config, process_name);
        if (!g_active.enabled) {
            if (config.log && config.log_unmatched) {
                LOGI("skip unmatched package=%s process=%s",
                     packageFromProcessName(process_name).c_str(),
                     process_name.c_str());
                closeModuleLogFile();
            }
            if (module_dir >= 0) close(module_dir);
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        openModuleLogFile(module_dir);
        if (hasPropertyOverrides(g_active.profile)) {
            installSystemPropertiesHooks(api_, env_);
        }
        if (g_active.native_property_hook && hasPropertyOverrides(g_active.profile)) {
            if (heavyHooksAllowed()) {
                registerPropertyPltHooks(api_);
            } else if (g_active.log) {
                LOGW("skip native property PLT hook for wildcard scope; set allow_wildcard_heavy_hooks=true to force");
            }
        }
        if (module_dir >= 0) close(module_dir);
        if (g_active.log) {
            LOGI("enabled package=%s process=%s profile=%s properties=%zu build=%zu app_features=%zu",
                 g_active.package_name.c_str(),
                 g_active.process_name.c_str(),
                 g_active.profile_name.c_str(),
                 g_active.profile.properties.size(),
                 g_active.profile.build_fields.size(),
                 g_active.profile.app_features.size());
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!g_active.enabled) return;
        if (needsArtHooks(g_active)) {
            const int module_dir = api_->getModuleDir();
            loadHookBridgeDex(env_, module_dir);
            if (module_dir >= 0) close(module_dir);
            installArtHooks(env_);
        }
        applyBuildFields(env_);
        applyLocale(env_);
        applyJavaSystemProperties(env_);
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
};

} // namespace

REGISTER_ZYGISK_MODULE(OOSRegionFaker)
REGISTER_ZYGISK_COMPANION(companionLogHandler)
