/****************************************************************************
 *
 * (c) 2009-2024 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#include "OpenSSLPQCSettings.h"
#include "QGCLoggingCategory.h"
#include "pqc_tls_wrapper.h"

#include <QtQml/QQmlEngine>

QGC_LOGGING_CATEGORY(OpenSSLPQCLog, "qgc.etri.pqc")

// ========== JNI Callback Management ==========
static OpenSSLPQCSettings* g_pqcSettingsInstance = nullptr;
static QString s_currentImportTarget = "";

// ========== Constructor ==========
OpenSSLPQCSettings::OpenSSLPQCSettings(QObject *parent) : QObject(parent)
{
    qCDebug(OpenSSLPQCLog) << "OpenSSLPQCSettings Singleton created";
    
#if defined(Q_OS_ANDROID)
    registerJNICallback();
#endif
}

// ========== Server Configuration Setters ==========

void OpenSSLPQCSettings::setServerIpAddress(const QString& address)
{
    if (_serverIpAddress != address) {
        _serverIpAddress = address;
        qCDebug(OpenSSLPQCLog) << "[OpenSSL-Server] IP Address:" << address;
        emit serverIpAddressChanged(address);
    }
}

void OpenSSLPQCSettings::setServerPortNumber(const QString& port)
{
    if (_serverPortNumber != port) {
        _serverPortNumber = port;
        qCDebug(OpenSSLPQCLog) << "[OpenSSL-Server] Port:" << port;
        emit serverPortNumberChanged(port);
    }
}

void OpenSSLPQCSettings::setServerConnected(bool connected)
{
    if (_serverConnected != connected) {
        _serverConnected = connected;
        qCDebug(OpenSSLPQCLog) << "[OpenSSL-Server] Status:" << (connected ? "CONNECTED" : "DISCONNECTED");
        emit serverConnectedChanged(connected);
    }
}

// ========== Routing Configuration Setters ==========

void OpenSSLPQCSettings::setRoutingPortNumber(const QString& port)
{
    if (_routingPortNumber != port) {
        _routingPortNumber = port;
        qCDebug(OpenSSLPQCLog) << "[OpenSSL-Routing] Port:" << port;
        emit routingPortNumberChanged(port);
    }
}

void OpenSSLPQCSettings::setRoutingConnected(bool connected)
{
    if (_routingConnected != connected) {
        _routingConnected = connected;
        qCDebug(OpenSSLPQCLog) << "[OpenSSL-Routing] Status:" << (connected ? "CONNECTED" : "DISCONNECTED");
        emit routingConnectedChanged(connected);
    }
}

// ========== Credential Setters ==========

void OpenSSLPQCSettings::setCaBundleFilePath(const QString& path)
{
    if (_caBundleFilePath != path) {
        _caBundleFilePath = path;
        qCDebug(OpenSSLPQCLog) << "[OpenSSL-Credentials] CA Bundle:" << path;
        emit caBundleFilePathChanged(path);
    }
}

void OpenSSLPQCSettings::setClientCertFilePath(const QString& path)
{
    if (_clientCertFilePath != path) {
        _clientCertFilePath = path;
        qCDebug(OpenSSLPQCLog) << "[OpenSSL-Credentials] Client Cert:" << path;
        emit clientCertFilePathChanged(path);
    }
}

// ========== Server Connection Methods ==========

void OpenSSLPQCSettings::connectToServer()
{
    qCDebug(OpenSSLPQCLog) << "";
    qCDebug(OpenSSLPQCLog) << "========== SERVER CONNECT REQUEST ==========";
    qCDebug(OpenSSLPQCLog) << "  IP Address      :" << _serverIpAddress;
    qCDebug(OpenSSLPQCLog) << "  Port            :" << _serverPortNumber;
    qCDebug(OpenSSLPQCLog) << "  CA Bundle       :" << _caBundleFilePath;
    qCDebug(OpenSSLPQCLog) << "  Client Cert     :" << _clientCertFilePath;
    qCDebug(OpenSSLPQCLog) << "==========================================";
    qCDebug(OpenSSLPQCLog) << "";
    
    // TODO: Implement actual server connection logic
    setServerConnected(true);
}

void OpenSSLPQCSettings::disconnectFromServer()
{
    qCDebug(OpenSSLPQCLog) << "";
    qCDebug(OpenSSLPQCLog) << "========== SERVER DISCONNECT REQUEST ==========";
    qCDebug(OpenSSLPQCLog) << "============================================";
    qCDebug(OpenSSLPQCLog) << "";
    
    // TODO: Implement actual server disconnection logic
    setServerConnected(false);
}

// ========== Routing Connection Methods ==========

void OpenSSLPQCSettings::routeConnection()
{
    qCDebug(OpenSSLPQCLog) << "";
    qCDebug(OpenSSLPQCLog) << "========== ROUTING CONNECT REQUEST ==========";
    qCDebug(OpenSSLPQCLog) << "  Port            :" << _routingPortNumber;
    qCDebug(OpenSSLPQCLog) << "==========================================";
    qCDebug(OpenSSLPQCLog) << "";
    
    // TODO: Implement actual routing connection logic
    setRoutingConnected(true);
}

void OpenSSLPQCSettings::disconnectRouting()
{
    qCDebug(OpenSSLPQCLog) << "";
    qCDebug(OpenSSLPQCLog) << "========== ROUTING DISCONNECT REQUEST ==========";
    qCDebug(OpenSSLPQCLog) << "==============================================";
    qCDebug(OpenSSLPQCLog) << "";
    
    // TODO: Implement actual routing disconnection logic
    setRoutingConnected(false);
}

// ========== File Import Methods (Android) ==========
void OpenSSLPQCSettings::registerJNICallback()
{
#if defined(Q_OS_ANDROID)
    g_pqcSettingsInstance = this;
    qCDebug(OpenSSLPQCLog) << "[OpenSSL-File-JNI] Callback registered";
#endif
}
void OpenSSLPQCSettings::callOpenPQCFileImportDialog(const QString& targetFilename)
{
    qCDebug(OpenSSLPQCLog) << "[OpenSSL-File] Opening file import dialog for:" << targetFilename;
    
#if defined(Q_OS_ANDROID)
    // 현재 import 대상 저장
    s_currentImportTarget = targetFilename;
    
    QString privateFolderPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    
    QStringList allowedExtensions;
    allowedExtensions << ".crt" << ".pem" << ".cer";
    
    qCDebug(OpenSSLPQCLog) << "[OpenSSL-File] Private folder:" << privateFolderPath;
    qCDebug(OpenSSLPQCLog) << "[OpenSSL-File] Allowed extensions:" << allowedExtensions;
    
    AndroidInterface::openPQCFileImportDialog(privateFolderPath, targetFilename, allowedExtensions);
#else
    qCDebug(OpenSSLPQCLog) << "[OpenSSL-File] Not on Android platform";
#endif
}

// ========== JNI Callback for File Import ==========
extern "C"
{
    JNIEXPORT void JNICALL Java_org_mavlink_qgroundcontrol_QGCActivity_onPQCImportResult(
        JNIEnv* env, jobject obj, jstring filePath)
    {
        if (g_pqcSettingsInstance == nullptr) {
            qCDebug(OpenSSLPQCLog) << "[OpenSSL-File-JNI] Settings instance is null";
            return;
        }
        
        const QString importedPath = QJniObject(filePath).toString();
        qCDebug(OpenSSLPQCLog) << "[OpenSSL-File-JNI] Callback received. File path:" << importedPath
                              << "Target:" << s_currentImportTarget;
        
        if (importedPath.isEmpty()) {
            qCDebug(OpenSSLPQCLog) << "[OpenSSL-File-JNI] Import cancelled or failed";
            return;
        }
        
        // 파일명으로 구분하여 적절한 프로퍼티 업데이트
        if (s_currentImportTarget == "ca_bundle.crt") {
            g_pqcSettingsInstance->setCaBundleFilePath(importedPath);
            qCDebug(OpenSSLPQCLog) << "[OpenSSL-File] CA Bundle imported:" << importedPath;
        } else if (s_currentImportTarget == "client_cert.crt") {
            g_pqcSettingsInstance->setClientCertFilePath(importedPath);
            qCDebug(OpenSSLPQCLog) << "[OpenSSL-File] Client Certificate imported:" << importedPath;
        } else {
            qCDebug(OpenSSLPQCLog) << "[OpenSSL-File] Unknown import target:" << s_currentImportTarget;
        }
    }
}

// ========== File Copy Methods ==========
QString OpenSSLPQCSettings::getPrivateFolderPath() const
{
    QString path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    return path;
}

QString OpenSSLPQCSettings::copyAndGetAbsolutePath(const QString& contentUri, const QString& filename)
{
    // 빈 URI 체크 (파일 미선택)
    if (contentUri.isEmpty()) {
        qCDebug(OpenSSLPQCLog) << "[OpenSSL-File] File not selected (empty URI)";
        return "";
    }
    
    // 프라이빗 폴더 경로
    QString privateFolderPath = getPrivateFolderPath();
    QString targetFilePath = privateFolderPath + "/" + filename;
    
    // Source 파일 열기
    QFile sourceFile(contentUri);
    if (!sourceFile.open(QIODevice::ReadOnly)) {
        qCDebug(OpenSSLPQCLog) << "[OpenSSL-File] Failed to open source:" << contentUri 
                               << "Error:" << sourceFile.errorString();
        return "";
    }
    
    // Target 파일 쓰기 (자동 덮어쓰기)
    QFile targetFile(targetFilePath);
    if (!targetFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qCDebug(OpenSSLPQCLog) << "[OpenSSL-File] Failed to open target:" << targetFilePath 
                               << "Error:" << targetFile.errorString();
        sourceFile.close();
        return "";
    }
    
    // 파일 복사 (스트림 방식 - 메모리 효율)
    qint64 bytesWritten = targetFile.write(sourceFile.readAll());
    sourceFile.close();
    targetFile.close();
    
    // 성공 로깅
    qCDebug(OpenSSLPQCLog) << "[OpenSSL-File] File copied successfully:"
                           << "Source:" << contentUri
                           << "Target:" << targetFilePath
                           << "Size:" << bytesWritten << "bytes";
    
    return targetFilePath;  // 절대 경로 반환
}