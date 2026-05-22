/****************************************************************************
 *
 * Copyright (C) 2018 Pinecone Inc. All rights reserved.
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#include "AndroidInterface.h"
#include "QGCLoggingCategory.h"

#include <QtCore/QJniObject>
#include <QtCore/QJniEnvironment>

QGC_LOGGING_CATEGORY(AndroidInterfaceLog, "qgc.android.src.androidinterface")

namespace AndroidInterface
{

bool cleanJavaException()
{
    QJniEnvironment jniEnv;
    const bool result = jniEnv.checkAndClearExceptions();
    return result;
}

jclass getActivityClass()
{
    static jclass javaClass = nullptr;

    if (!javaClass) {
        QJniEnvironment env;
        if (!env.isValid()) {
            qCWarning(AndroidInterfaceLog) << "Invalid QJniEnvironment";
            return nullptr;
        }

        if (!QJniObject::isClassAvailable(kJniQGCActivityClassName)) {
            qCWarning(AndroidInterfaceLog) << "Class Not Available";
            return nullptr;
        }

        javaClass = env.findClass(kJniQGCActivityClassName);
        if (!javaClass) {
            qCWarning(AndroidInterfaceLog) << "Class Not Found";
            return nullptr;
        }

        env.checkAndClearExceptions();
    }

    return javaClass;
}

void setNativeMethods()
{
    qCDebug(AndroidInterfaceLog) << "Registering Native Functions";

    JNINativeMethod javaMethods[] {
        {"qgcLogDebug",   "(Ljava/lang/String;)V", reinterpret_cast<void *>(jniLogDebug)},
        {"qgcLogWarning", "(Ljava/lang/String;)V", reinterpret_cast<void *>(jniLogWarning)}
    };

    (void) AndroidInterface::cleanJavaException();

    jclass objectClass = AndroidInterface::getActivityClass();
    if(!objectClass) {
        qCWarning(AndroidInterfaceLog) << "Couldn't find class:" << objectClass;
        return;
    }

    QJniEnvironment jniEnv;
    jint val = jniEnv->RegisterNatives(objectClass, javaMethods, std::size(javaMethods));

    if (val < 0) {
        qCWarning(AndroidInterfaceLog) << "Error registering methods:" << val;
    } else {
        qCDebug(AndroidInterfaceLog) << "Native Functions Registered";
    }

    (void) AndroidInterface::cleanJavaException();
}

void jniLogDebug(JNIEnv *envA, jobject thizA, jstring messageA)
{
    Q_UNUSED(thizA);

    const char * const stringL = envA->GetStringUTFChars(messageA, nullptr);
    const QString logMessage = QString::fromUtf8(stringL);
    envA->ReleaseStringUTFChars(messageA, stringL);
    (void) QJniEnvironment::checkAndClearExceptions(envA);
    qCDebug(AndroidInterfaceLog) << logMessage;
}

void jniLogWarning(JNIEnv *envA, jobject thizA, jstring messageA)
{
    Q_UNUSED(thizA);

    const char * const stringL = envA->GetStringUTFChars(messageA, nullptr);
    const QString logMessage = QString::fromUtf8(stringL);
    envA->ReleaseStringUTFChars(messageA, stringL);
    (void) QJniEnvironment::checkAndClearExceptions(envA);
    qCWarning(AndroidInterfaceLog) << logMessage;
}

bool checkStoragePermissions()
{
    // Call the Java method to check and request storage permissions
    const bool hasPermission = QJniObject::callStaticMethod<jboolean>(
        kJniQGCActivityClassName, 
        "checkStoragePermissions", 
        "()Z"
    );
    
    if (hasPermission) {
        qCDebug(AndroidInterfaceLog) << "Storage permissions granted";
    } else {
        qCWarning(AndroidInterfaceLog) << "Storage permissions not granted";
    }
    
    return hasPermission;
}

QString getSDCardPath()
{
    if (!checkStoragePermissions()) {
        qCWarning(AndroidInterfaceLog) << "Storage Permission Denied";
        return QString();
    }

    const QJniObject result = QJniObject::callStaticObjectMethod(kJniQGCActivityClassName, "getSDCardPath", "()Ljava/lang/String;");
    if (!result.isValid()) {
        qCWarning(AndroidInterfaceLog) << "Call to java getSDCardPath failed: Invalid Result";
        return QString();
    }

    return result.toString();
}

void openPQCFileImportDialog(const QString& destPath, const QString& filename, const QStringList& allowedExtensions)
{
    qCDebug(AndroidInterfaceLog) << "openPQCFileImportDialog called"
                                 << "destPath:" << destPath
                                 << "filename:" << filename
                                 << "extensions count:" << allowedExtensions.size();
    
    // JNI 환경 변수 저장
    QJniEnvironment env;
    if (!env.isValid()) {
        qCWarning(AndroidInterfaceLog) << "Invalid JNI Environment";
        return;
    }
    
    // Java String 객체 생성
    QJniObject javaDestPath = QJniObject::fromString(destPath);
    QJniObject javaFilename = QJniObject::fromString(filename);
    
    // String class 찾기
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) {
        qCWarning(AndroidInterfaceLog) << "Failed to find String class";
        return;
    }
    
    // String[] 배열 생성
    jsize arraySize = static_cast<jsize>(allowedExtensions.size());
    jobjectArray javaExtArray = env->NewObjectArray(arraySize, stringClass, nullptr);
    if (!javaExtArray) {
        qCWarning(AndroidInterfaceLog) << "Failed to create String array";
        env->DeleteLocalRef(stringClass);
        return;
    }
    
    // 배열에 요소 추가
    for (jsize i = 0; i < arraySize; ++i) {
        QJniObject ext = QJniObject::fromString(allowedExtensions.at(i));
        env->SetObjectArrayElement(javaExtArray, i, ext.object());
    }
    
    // 메모리 정리
    env->DeleteLocalRef(stringClass);
    
    // Java 메서드 호출
    QJniObject::callStaticMethod<void>(
        kJniQGCActivityClassName,
        "openFileImportDialog",
        "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V",
        javaDestPath.object(),
        javaFilename.object(),
        javaExtArray
    );
    
    // 배열 메모리 정리
    env->DeleteLocalRef(javaExtArray);
    
    qCDebug(AndroidInterfaceLog) << "openPQCFileImportDialog completed";
}

void setKeepScreenOn(bool on)
{
    Q_UNUSED(on);

    //-- Screen is locked on while QGC is running on Android
}

} // namespace AndroidInterface
