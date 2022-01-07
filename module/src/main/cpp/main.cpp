#include <jni.h>
#include <sys/types.h>
#include <riru.h>
#include <malloc.h>
#include <cstring>
#include <config.h>
#include <dlfcn.h>
#include <vector>
#include "logging.h"

#ifdef __LP64__
constexpr const char* kZygoteNiceName = "zygote64";
constexpr const char* nextLoadSo = "/system/lib64/libminitool.so";
#else
constexpr const char* kZygoteNiceName = "zygote";
constexpr const char* nextLoadSo = "/system/lib/libminitool.so";
#endif
static char nice_process_name[256] = {0};
static char package_name[256] = {0};

static jint my_uid = 0;

static bool isApp(int uid) {
    if (uid < 0) {
        return false;
    }
    int appId = uid % 100000;

    // limit only regular app, or strange situation will happen, such as zygote process not start (dead for no reason and leave no clues?)
    // https://android.googlesource.com/platform/frameworks/base/+/android-9.0.0_r8/core/java/android/os/UserHandle.java#151
    return appId >= 10000 && appId <= 19999;
}

static void
my_forkAndSpecializePre(JNIEnv *env, jint *uid, jstring *niceName, jstring *appDataDir) {
    //LOGI("Q_M xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx %s", "forkAndSpecializePre");
    my_uid = *uid;
    if (!isApp(my_uid)) {
        return;
    }

    const char *tablePath = (env->GetStringUTFChars(*niceName, 0));
    sprintf(nice_process_name, "%s", tablePath);
    delete tablePath;

    if (!appDataDir) {
        LOGI(" forkAndSpecializePre appDataDir null");
        return;
    }

    const char *app_data_dir = env->GetStringUTFChars(*appDataDir, NULL);
    if (app_data_dir == nullptr) {
        return;
    }
    //LOGI("Q_M xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx app_data_dir %s",app_data_dir);

    int user = 0;
    if (sscanf(app_data_dir, "/data/%*[^/]/%d/%s", &user, package_name) != 2) {
        if (sscanf(app_data_dir, "/data/%*[^/]/%s", package_name) != 1) {
            package_name[0] = '\0';
            LOGI("can't parse %s", app_data_dir);
        }
    }
    env->ReleaseStringUTFChars(*appDataDir, app_data_dir);

}

static void my_forkAndSpecializePost(JNIEnv *env) {
    if (!isApp(my_uid)) {
        return;
    }

//    if (!strstr(nice_process_name, "com.smile.gifmaker")
//        && !strstr(nice_process_name, "com.ss.android.ugc.aweme")
//        && !strstr(nice_process_name, "com.xingin.xhs")
//            ) {
//        return;
//    }

    char *app_list;
//    const char *filepath = "/data/local/tmp/finstaller/fs/app.list";
    const char *filepath = "/data/local/tmp/app.list";
    const char *disable = "/data/local/tmp/finstaller/fs/disable";
    FILE *fp = nullptr;
    FILE *fp_disable = nullptr;
    fp_disable = fopen(disable, "r");
    if(fp_disable!=nullptr){
        LOGE("frida is disabled");
        return;
    }
    fp = fopen(filepath, "r");
    if (fp != nullptr) {

        fseek(fp, 0, SEEK_END);
        int fileLen = ftell(fp);
        app_list = (char *) malloc(sizeof(char) * (fileLen + 1));
        fseek(fp, 0, SEEK_SET);
//        size_t count = fread(app_list, fileLen, sizeof(char), fp);
        size_t count = fread(app_list, 1, fileLen, fp);
        app_list[count] = '\0';
        fclose(fp);

        LOGI(" app list: %s", app_list);
    } else {
        app_list = "";
    }

    if (!strstr(app_list, package_name)) {
        return;
    }

    LOGI(" nice_process_name=%s, pkg=%s,uid=%d, isApp= %d",
         nice_process_name, package_name, my_uid,
         isApp(my_uid));

    //添加这种机制，就可以提前设置进程名， 从而让frida 的gadget 能够识别到
    jclass java_Process = env->FindClass("android/os/Process");
    if (java_Process != nullptr && isApp(my_uid)) {
        jmethodID mtd_setArgV0 = env->GetStaticMethodID(java_Process, "setArgV0",
                                                        "(Ljava/lang/String;)V");
        jstring name = env->NewStringUTF(nice_process_name);
        env->CallStaticVoidMethod(java_Process, mtd_setArgV0, name);

        void *handle = dlopen(nextLoadSo, RTLD_LAZY);
        if (!handle) {
            //        LOGE("%s",dlerror());
            LOGE(" %s loaded in libgadget error %s", nice_process_name, dlerror());
        } else {
            LOGI(" %s load ' %s ' success ", nice_process_name,nextLoadSo);
        }
    }
}

static void forkAndSpecializePre(
        JNIEnv *env, jclass clazz, jint *uid, jint *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jint *mountExternal, jstring *seInfo, jstring *niceName,
        jintArray *fdsToClose, jintArray *fdsToIgnore, jboolean *is_child_zygote,
        jstring *instructionSet, jstring *appDataDir, jboolean *isTopApp, jobjectArray *pkgDataInfoList,
        jobjectArray *whitelistedDataInfoList, jboolean *bindMountAppDataDirs, jboolean *bindMountAppStorageDirs) {
    // Called "before" com_android_internal_os_Zygote_nativeForkAndSpecialize in frameworks/base/core/jni/com_android_internal_os_Zygote.cpp
    // Parameters are pointers, you can change the value of them if you want
    // Some parameters are not exist is older Android versions, in this case, they are null or 0
    my_forkAndSpecializePre(env, uid, niceName, appDataDir);
    
}

static void forkAndSpecializePost(JNIEnv *env, jclass clazz, jint res) {
    // Called "after" com_android_internal_os_Zygote_nativeForkAndSpecialize in frameworks/base/core/jni/com_android_internal_os_Zygote.cpp
    // "res" is the return value of com_android_internal_os_Zygote_nativeForkAndSpecialize

    if (res == 0) {
        // In app process

        // When unload allowed is true, the module will be unloaded (dlclose) by Riru
        // If this modules has hooks installed, DONOT set it to true, or there will be SIGSEGV
        // This value will be automatically reset to false before the "pre" function is called
        my_forkAndSpecializePost(env);
        riru_set_unload_allowed(false);
    } else {
        // In zygote process
    }
}

static void specializeAppProcessPre(
        JNIEnv *env, jclass clazz, jint *uid, jint *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jint *mountExternal, jstring *seInfo, jstring *niceName,
        jboolean *startChildZygote, jstring *instructionSet, jstring *appDataDir,
        jboolean *isTopApp, jobjectArray *pkgDataInfoList, jobjectArray *whitelistedDataInfoList,
        jboolean *bindMountAppDataDirs, jboolean *bindMountAppStorageDirs) {
    // Called "before" com_android_internal_os_Zygote_nativeSpecializeAppProcess in frameworks/base/core/jni/com_android_internal_os_Zygote.cpp
    // Parameters are pointers, you can change the value of them if you want
    // Some parameters are not exist is older Android versions, in this case, they are null or 0
     my_forkAndSpecializePre(env, uid, niceName, appDataDir);
}

static void specializeAppProcessPost(
        JNIEnv *env, jclass clazz) {
    // Called "after" com_android_internal_os_Zygote_nativeSpecializeAppProcess in frameworks/base/core/jni/com_android_internal_os_Zygote.cpp

    // When unload allowed is true, the module will be unloaded (dlclose) by Riru
    // If this modules has hooks installed, DONOT set it to true, or there will be SIGSEGV
    // This value will be automatically reset to false before the "pre" function is called
    my_forkAndSpecializePost(env);
    riru_set_unload_allowed(false);
}

static void forkSystemServerPre(
        JNIEnv *env, jclass clazz, uid_t *uid, gid_t *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jlong *permittedCapabilities, jlong *effectiveCapabilities) {
    // Called "before" com_android_internal_os_Zygote_forkSystemServer in frameworks/base/core/jni/com_android_internal_os_Zygote.cpp
    // Parameters are pointers, you can change the value of them if you want
    // Some parameters are not exist is older Android versions, in this case, they are null or 0
}

static void forkSystemServerPost(JNIEnv *env, jclass clazz, jint res) {
    // Called "after" com_android_internal_os_Zygote_forkSystemServer in frameworks/base/core/jni/com_android_internal_os_Zygote.cpp

    if (res == 0) {
        // In system server process
    } else {
        // In zygote process
    }
}

static void onModuleLoaded() {
    // Called when this library is loaded and "hidden" by Riru (see Riru's hide.cpp)

    // If you want to use threads, start them here rather than the constructors
    // __attribute__((constructor)) or constructors of static variables,
    // or the "hide" will cause SIGSEGV
}

extern "C" {

int riru_api_version;
const char *riru_magisk_module_path = nullptr;
int *riru_allow_unload = nullptr;

static auto module = RiruVersionedModuleInfo{
        .moduleApiVersion = riru::moduleApiVersion,
        .moduleInfo= RiruModuleInfo{
                .supportHide = true,
                .version = riru::moduleVersionCode,
                .versionName = riru::moduleVersionName,
                .onModuleLoaded = onModuleLoaded,
                .forkAndSpecializePre = forkAndSpecializePre,
                .forkAndSpecializePost = forkAndSpecializePost,
                .forkSystemServerPre = forkSystemServerPre,
                .forkSystemServerPost = forkSystemServerPost,
                .specializeAppProcessPre = specializeAppProcessPre,
                .specializeAppProcessPost = specializeAppProcessPost
        }
};

RiruVersionedModuleInfo *init(Riru *riru) {
    auto core_max_api_version = riru->riruApiVersion;
    riru_api_version = core_max_api_version <= riru::moduleApiVersion ? core_max_api_version : riru::moduleApiVersion;
    module.moduleApiVersion = riru_api_version;

    riru_magisk_module_path = strdup(riru->magiskModulePath);
    if (riru_api_version >= 25) {
        riru_allow_unload = riru->allowUnload;
    }
    return &module;
}
}
