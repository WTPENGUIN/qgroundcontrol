/****************************************************************************
 *
 * Copyright (C) 2018 Pinecone Inc. All rights reserved.
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#pragma once

#include <QtCore/QString>
#include <QtCore/QLoggingCategory>

#include <jni.h>

Q_DECLARE_LOGGING_CATEGORY(AndroidInterfaceLog)

namespace AndroidInterface
{
    bool cleanJavaException();
    jclass getActivityClass();
    void setNativeMethods();
    void jniLogDebug(JNIEnv *envA, jobject thizA, jstring messageA);
    void jniLogWarning(JNIEnv *envA, jobject thizA, jstring messageA);
    bool checkStoragePermissions();
    QString getSDCardPath();
    void setKeepScreenOn(bool on);

    /**
     * Opens file import dialog for PQC certificate files
     * @param destPath              Destination directory path
     * @param filename              Fixed filename for copied file
     * @param allowedExtensions     Allowed file extensions (e.g., ".crt", ".pem", ".cer")
     */
    void openPQCFileImportDialog(const QString& destPath, const QString& filename, const QStringList& allowedExtensions);

    constexpr const char *kJniQGCActivityClassName = "org/mavlink/qgroundcontrol/QGCActivity";
};
