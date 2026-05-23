#include <jni.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <unwind.h>
#include <dlfcn.h>
#include <android/log.h>

#define LOG_TAG "STACK_CHECK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)


// Mục đích chính đoạn native dùng _Unwind_Backtrace để trace stack
// Check call stack, addr lưu vào pc sau đó đi map pc này ứng với lib vào trong maps
// Nếu lib đó sus => detect

struct NativeFrameInfo {
    uintptr_t pc = 0;
    std::string moduleName;
    std::string symbolName;
    std::string mapPerms;
    std::string mapPath;
};

struct MapInfo {
    uintptr_t start = 0;
    uintptr_t end = 0;
    std::string perms;
    std::string path;
    bool found = false;
};

struct BacktraceState {
    uintptr_t *current = nullptr;
    uintptr_t *end = nullptr;
};

static _Unwind_Reason_Code unwindCallback(
        _Unwind_Context *context,
        void *arg
) {
    BacktraceState *state = reinterpret_cast<BacktraceState *>(arg);

    uintptr_t pc = static_cast<uintptr_t>(_Unwind_GetIP(context));

    if (pc != 0 && state->current < state->end) {
        *state->current++ = pc;
        return _URC_NO_REASON;
    }

    return _URC_END_OF_STACK;
}

static std::vector<uintptr_t> captureBacktrace(size_t maxFrames) {
    std::vector<uintptr_t> frames(maxFrames);

    BacktraceState state;
    state.current = frames.data();
    state.end = frames.data() + frames.size();

    _Unwind_Backtrace(unwindCallback, &state);

    frames.resize(state.current - frames.data());

    return frames;
}

static std::string toLowerString(std::string s) {
    std::transform(
            s.begin(),
            s.end(),
            s.begin(),
            [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            }
    );

    return s;
}

static std::string ptrToHex(uintptr_t ptr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << ptr;
    return oss.str();
}

static bool containsAnyKeyword(
        const std::string &text,
        const std::vector<std::string> &keywords
) {
    std::string lower = toLowerString(text);

    for (const std::string &keyword : keywords) {
        if (lower.find(keyword) != std::string::npos) {
            return true;
        }
    }

    return false;
}

/*
 * Tìm dòng /proc/self/maps chứa địa chỉ pc.
 *
 * Ví dụ maps:
 * 7e1d9f20c000-7e1d9f26d000 r-xp 00c00000 ... /data/app/.../base.apk
 */
static bool findMapForAddress(uintptr_t pc, MapInfo &out) {
    FILE *fp = std::fopen("/proc/self/maps", "r");

    if (fp == nullptr) {
        return false;
    }

    char line[4096];

    while (std::fgets(line, sizeof(line), fp) != nullptr) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        unsigned long long offset = 0;
        unsigned long long inode = 0;

        char perms[8] = {0};
        char dev[32] = {0};
        char path[4096] = {0};

        int count = std::sscanf(
                line,
                "%llx-%llx %7s %llx %31s %llu %4095[^\n]",
                &start,
                &end,
                perms,
                &offset,
                dev,
                &inode,
                path
        );

        if (count >= 6) {
            if (pc >= static_cast<uintptr_t>(start) &&
                pc < static_cast<uintptr_t>(end)) {

                out.start = static_cast<uintptr_t>(start);
                out.end = static_cast<uintptr_t>(end);
                out.perms = perms;

                if (count == 7) {
                    out.path = path;
                } else {
                    out.path = "";
                }

                out.found = true;
                std::fclose(fp);
                return true;
            }
        }
    }

    std::fclose(fp);
    return false;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_testapp_MainActivity_nativeShowStack(
        JNIEnv *env,
        jobject,
        jstring label
) {
    const char *labelChars = env->GetStringUTFChars(label, nullptr);
    std::string labelText = labelChars ? labelChars : "";
    env->ReleaseStringUTFChars(label, labelChars);

    std::vector<uintptr_t> pcs = captureBacktrace(64);

    const std::vector<std::string> suspiciousKeywords = {
            "frida",
            "gum",
            "gadget",
            "xposed",
            "lsposed",
//            "substrate",
//            "riru",
//            "zygisk"
    };

    bool hasOwnLibOrBaseApk = false;
    bool hasArtRuntime = false;
    bool hasJniBridgeLikeFrame = false;
    bool hasSuspiciousModule = false;
    bool hasAnonymousExecutable = false;

    std::vector<NativeFrameInfo> frames;

    for (uintptr_t pc : pcs) {
        NativeFrameInfo frame;
        frame.pc = pc;

        Dl_info info;
        std::memset(&info, 0, sizeof(info));

        /*
         * dladdr() ánh xạ địa chỉ pc về module/symbol nếu có.
         */
        if (dladdr(reinterpret_cast<void *>(pc), &info) != 0) {
            if (info.dli_fname != nullptr) {
                frame.moduleName = info.dli_fname;
            }

            if (info.dli_sname != nullptr) {
                frame.symbolName = info.dli_sname;
            }
        }

        /*
         * /proc/self/maps cho biết pc nằm trong vùng memory nào,
         * permission là gì và file backing là gì.
         */
        MapInfo mapInfo;
        if (findMapForAddress(pc, mapInfo)) {
            frame.mapPerms = mapInfo.perms;
            frame.mapPath = mapInfo.path;
        }

        std::string combined =
                frame.moduleName + " " +
                frame.symbolName + " " +
                frame.mapPath;

        std::string lower = toLowerString(combined);

        /*
         * Trên Android, native library có thể được map từ base.apk,
         * nên maps path có thể là base.apk thay vì libintegritydemo.so.
         */
        if (lower.find("libintegritydemo.so") != std::string::npos ||
            lower.find("base.apk") != std::string::npos ||
            lower.find("com.example.testapp") != std::string::npos) {
            hasOwnLibOrBaseApk = true;
        }

        /*
         * ART runtime thường xuất hiện khi luồng đi từ Java/Kotlin xuống JNI/native.
         */
        if (lower.find("libart.so") != std::string::npos ||
            lower.find("libartbase.so") != std::string::npos ||
            lower.find("libandroid_runtime.so") != std::string::npos) {
            hasArtRuntime = true;
        }

        /*
         * JNI bridge-like signal. Không phải máy nào cũng resolve symbol có chữ JNI,
         * nên đây chỉ là tín hiệu phụ.
         */
        if (lower.find("jni") != std::string::npos ||
            lower.find("libnativehelper.so") != std::string::npos ||
            lower.find("libandroid_runtime.so") != std::string::npos) {
            hasJniBridgeLikeFrame = true;
        }

        if (containsAnyKeyword(combined, suspiciousKeywords)) {
            hasSuspiciousModule = true;
        }

        /*
         * Anonymous executable memory là tín hiệu đáng ngờ.
         * Nhưng ART/JIT cũng có thể tạo vùng executable động,
         * nên không nên kết luận chỉ dựa vào tín hiệu này.
         */
//        if (frame.mapPerms.find('x') != std::string::npos &&
//            frame.mapPath.empty()) {
//            hasAnonymousExecutable = true;
//        }

        frames.push_back(frame);
    }

    std::ostringstream result;

    result << "[NATIVE STACK REPORT]\n";
    result << "label: " << labelText << "\n\n";

    result << "Expected high-level flow:\n";
    result << "Kotlin MainActivity\n";
    result << "  -> ART runtime\n";
    result << "  -> JNI bridge\n";
    result << "  -> libintegritydemo.so / base.apk\n";
    result << "  -> nativeShowStack()\n\n";

    result << "Signals:\n";
    result << "- own lib/base.apk frame: "
           << (hasOwnLibOrBaseApk ? "true" : "false") << "\n";

    result << "- ART runtime frame: "
           << (hasArtRuntime ? "true" : "false") << "\n";

    result << "- JNI bridge-like frame: "
           << (hasJniBridgeLikeFrame ? "true" : "false") << "\n";

    result << "- suspicious module keyword: "
           << (hasSuspiciousModule ? "true" : "false") << "\n";

    result << "- anonymous executable frame: "
           << (hasAnonymousExecutable ? "true" : "false") << "\n\n";

    if (hasSuspiciousModule || hasAnonymousExecutable) {
        result << "native status: SUSPICIOUS - possible hook/instrumentation frame\n\n";
    } else if (hasOwnLibOrBaseApk && hasArtRuntime) {
        result << "native status: NORMAL-LIKE - expected app/native/runtime frames found\n\n";
    } else {
        result << "native status: INCONCLUSIVE - expected frames are incomplete\n\n";
    }

    result << "Native frames:\n";

    for (size_t i = 0; i < frames.size(); i++) {
        const NativeFrameInfo &f = frames[i];

        std::string combined =
                f.moduleName + " " +
                f.symbolName + " " +
                f.mapPath;

        bool suspicious = containsAnyKeyword(combined, suspiciousKeywords);
        bool anonExec = f.mapPerms.find('x') != std::string::npos &&
                        f.mapPath.empty();

        result << "#"
               << i
               << " pc="
               << ptrToHex(f.pc);

        if (suspicious) {
            result << "  [SUSPICIOUS]";
        }

        if (anonExec) {
            result << "  [ANON_EXEC]";
        }

        result << "\n";

        result << "   module: "
               << (f.moduleName.empty() ? "<unknown>" : f.moduleName)
               << "\n";

        result << "   symbol: "
               << (f.symbolName.empty() ? "<unknown>" : f.symbolName)
               << "\n";

        result << "   maps: "
               << (f.mapPerms.empty() ? "----" : f.mapPerms)
               << " "
               << (f.mapPath.empty() ? "<anonymous>" : f.mapPath)
               << "\n";
    }

    LOGI("%s", result.str().c_str());

    return env->NewStringUTF(result.str().c_str());
}