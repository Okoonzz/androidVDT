#include <jni.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <mutex>
#include <cstdint>
#include <android/log.h>

#define LOG_TAG "PROLOGUE_CHECK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static constexpr size_t PROLOGUE_SIZE = 32;

static uint8_t g_baseline[PROLOGUE_SIZE];
static bool g_hasBaseline = false;
static std::mutex g_lock;

extern "C"
//Giữ tên symbol là sensitive_check, không bị C++ name mangling
__attribute__((visibility("default")))
//Export symbol để Frida tìm được
__attribute__((noinline))
//Không cho compiler inline hàm
__attribute__((used))
//Không cho compiler loại bỏ hàm
int sensitive_check(int x) {
    volatile int v = x;

    for (int i = 0; i < 8; i++) {
        v = (v * 3) + i;
    }

    if (v == 123456) {
        return 1;
    }

    return v;
}
//lấy địa chỉ thật của sensitive_check trong memory
static uintptr_t getSensitiveCheckAddress() {
    uintptr_t addr = reinterpret_cast<uintptr_t>(&sensitive_check);
    addr &= ~static_cast<uintptr_t>(1);
    return addr;
}

static std::string bytesToHex(const uint8_t *data, size_t len) {
    std::ostringstream oss;

    for (size_t i = 0; i < len; i++) {
        oss << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(data[i]);

        if (i + 1 < len) {
            oss << " ";
        }
    }

    return oss.str();
}

static std::string ptrToHex(uintptr_t ptr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << ptr;
    return oss.str();
}

//được kotlin gọi khi press Init Baseline Bytes
extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_testapp_MainActivity_initBaseline(
        JNIEnv *env,
        jobject) {

    std::lock_guard<std::mutex> lock(g_lock);

    //Lấy địa chỉ sensitive_check
    uintptr_t addr = getSensitiveCheckAddress();

    //Copy 32 bytes sạch ban đầu của sensitive_check
    std::memcpy(g_baseline, reinterpret_cast<void *>(addr), PROLOGUE_SIZE);
    g_hasBaseline = true;

    std::ostringstream result;
    result << "[INIT BASELINE]\n";
    result << "sensitive_check address: " << ptrToHex(addr) << "\n";
    result << "baseline bytes:\n";
    result << bytesToHex(g_baseline, PROLOGUE_SIZE) << "\n";

    LOGI("%s", result.str().c_str());

    return env->NewStringUTF(result.str().c_str());
}

//được kotlin gọi khi press Check Current Bytes
extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_testapp_MainActivity_checkPrologue(
        JNIEnv *env,
        jobject) {

    std::lock_guard<std::mutex> lock(g_lock);

    uintptr_t addr = getSensitiveCheckAddress();

    uint8_t current[PROLOGUE_SIZE];

    // đọc 32 bytes đầu hiện tại của sensitive_check trong mem
    std::memcpy(current, reinterpret_cast<void *>(addr), PROLOGUE_SIZE);

    bool match = false;

    if (g_hasBaseline) {
        match = std::memcmp(g_baseline, current, PROLOGUE_SIZE) == 0;
    }

    std::ostringstream result;
    result << "[CHECK PROLOGUE]\n";
    result << "sensitive_check address: " << ptrToHex(addr) << "\n\n";

    if (!g_hasBaseline) {
        result << "baseline: NOT INITIALIZED\n\n";
    } else {
        result << "baseline bytes:\n";
        result << bytesToHex(g_baseline, PROLOGUE_SIZE) << "\n\n";
    }

    result << "current bytes:\n";
    result << bytesToHex(current, PROLOGUE_SIZE) << "\n\n";

    if (!g_hasBaseline) {
        result << "status: BASELINE NOT READY\n";
    } else if (match) {
        result << "status: MATCH - native function looks intact\n";
    } else {
        result << "status: MISMATCH - native function may be hooked/modified\n";
    }

    LOGI("%s", result.str().c_str());

    return env->NewStringUTF(result.str().c_str());
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_testapp_MainActivity_callSensitiveCheck(
        JNIEnv *,
        jobject,
        jint x) {

    return sensitive_check(x);
}