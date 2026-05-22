/****************************************************************************
 *
 * (c) 2009-2024 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#include "OpenSSLPQCSettings.h"
#include "PQCTLSConnectionWorker.h"
#include "QGCLoggingCategory.h"
#include "pqc_tls_wrapper.h"

#include <QtQml/QQmlEngine>

QGC_LOGGING_CATEGORY(OpenSSLPQCLog, "qgc.etri.pqc")

// ========== JNI Callback Management ==========
static OpenSSLPQCSettings* g_pqcSettingsInstance = nullptr;
static QString s_currentImportTarget = "";

// ========== Constructor / Destructor ==========

OpenSSLPQCSettings::OpenSSLPQCSettings(QObject *parent) : QObject(parent)
{
    qCDebug(OpenSSLPQCLog) << "OpenSSLPQCSettings Singleton created";
    
#if defined(Q_OS_ANDROID)
    registerJNICallback();
#endif
}

OpenSSLPQCSettings::~OpenSSLPQCSettings()
{
    // 1. Disconnect from server (closes connection and cleans up notifiers)
    disconnectFromServer();
    
    // 2. Clean up worker thread
    if (_connectionWorker) {
        qCDebug(OpenSSLPQCLog) << "[Destructor] Cleaning up worker thread...";
        if (_connectionWorker->isRunning()) {
            _connectionWorker->requestInterruption();
            _connectionWorker->wait(5000);
        }
        _connectionWorker->deleteLater();
        _connectionWorker = nullptr;
    }
    
    // 3. Cleanup OpenSSL library
    pqc_tls_cleanup_library();
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

// ========== PQC TLS Logging Callback ==========

void OpenSSLPQCSettings::logCallback(void* userData, const char* msg)
{
    if (!msg) return;
    
    QString msgStr = QString::fromUtf8(msg);
    
    // 1. Debug log output
    qCDebug(OpenSSLPQCLog) << "[PQC-C-Library]" << msgStr;
    
    // 2. Filter out read/write logs
    if (msgStr.contains("Sent bytes:", Qt::CaseInsensitive) ||
        msgStr.contains("Received bytes:", Qt::CaseInsensitive) ||
        msgStr.contains("Write:", Qt::CaseInsensitive) ||
        msgStr.contains("Read:", Qt::CaseInsensitive)) {
        return;  // Filtered out
    }
    
    // 3. Append to TLS log buffer
    OpenSSLPQCSettings* self = static_cast<OpenSSLPQCSettings*>(userData);
    if (self) {
        self->appendTlsLog(msgStr);
    }
}

// ========== Server Connection Methods ==========

void OpenSSLPQCSettings::connectToServer()
{
    qCDebug(OpenSSLPQCLog) << "";
    qCDebug(OpenSSLPQCLog) << "========== SERVER CONNECT REQUEST (ASYNC) ==========";
    qCDebug(OpenSSLPQCLog) << "  IP Address      :" << _serverIpAddress;
    qCDebug(OpenSSLPQCLog) << "  Port            :" << _serverPortNumber;
    qCDebug(OpenSSLPQCLog) << "====================================================";
    qCDebug(OpenSSLPQCLog) << "";
    
    // Prevent duplicate connections
    if (_serverConnected || _isConnecting) {
        qCDebug(OpenSSLPQCLog) << "[PQC-Connect] Already connected or connecting";
        return;
    }
    
    // Input validation
    if (_serverIpAddress.isEmpty()) {
        qCCritical(OpenSSLPQCLog) << "[PQC-Connect] Error: Server IP address is empty";
        setServerConnected(false);
        return;
    }
    
    if (_serverPortNumber.isEmpty()) {
        qCCritical(OpenSSLPQCLog) << "[PQC-Connect] Error: Server port number is empty";
        setServerConnected(false);
        return;
    }
    
    if (_caBundleFilePath.isEmpty()) {
        qCCritical(OpenSSLPQCLog) << "[PQC-Connect] Error: CA bundle file path is empty";
        setServerConnected(false);
        return;
    }
    
    if (_clientCertFilePath.isEmpty()) {
        qCCritical(OpenSSLPQCLog) << "[PQC-Connect] Error: Client certificate file path is empty";
        setServerConnected(false);
        return;
    }
    
    // Port number conversion
    bool portOk = false;
    int port = _serverPortNumber.toInt(&portOk);
    if (!portOk || port <= 0 || port > 65535) {
        qCCritical(OpenSSLPQCLog) << "[PQC-Connect] Error: Invalid port number" << _serverPortNumber;
        setServerConnected(false);
        return;
    }
    
    // Update status: starting connection attempt
    setServerConnected(false);
    _isConnecting = true;
    emit connectionStatusChanged("connecting");
    
    qCDebug(OpenSSLPQCLog) << "[PQC-Connect] Starting async connection...";
    
    // Clean up existing worker thread before creating a new one
    // QThread can only be started once, so we must create a new instance for each connection
    if (_connectionWorker) {
        qCDebug(OpenSSLPQCLog) << "[PQC-Connect] Cleaning up previous worker thread...";
        if (_connectionWorker->isRunning()) {
            _connectionWorker->requestInterruption();
            _connectionWorker->wait(5000);
        }
        _connectionWorker->deleteLater();
        _connectionWorker = nullptr;
    }
    
    // Create a new worker thread for this connection attempt
    _connectionWorker = new PQCTLSConnectionWorker(this);
    qCDebug(OpenSSLPQCLog) << "[PQC-Connect] New worker thread created";
    
    // Connect worker finished signal
    connect(_connectionWorker, static_cast<void(PQCTLSConnectionWorker::*)(bool, void*)>(&PQCTLSConnectionWorker::finished),
            this, [this](bool success, void* ctx) {
        if (success && ctx) {
            qCDebug(OpenSSLPQCLog) << "[PQC-Main] ✅ Connection established!";
            _pqcCtx = static_cast<pqc_tls_ctx_t*>(ctx);
            setupSocketNotifiers();
            setServerConnected(true);
            emit connectionStatusChanged("connected");
        } else {
            qCCritical(OpenSSLPQCLog) << "[PQC-Main] ❌ Connection failed";
            setServerConnected(false);
            emit connectionStatusChanged("error");
            emit connectionError("Failed to establish PQC TLS connection");
        }
        _isConnecting = false;
    });
    
    // connect(_connectionWorker, &QThread::finished, _connectionWorker, &QObject::deleteLater);
    connect(_connectionWorker, &QThread::finished, this, [this]() {
        _connectionWorker->deleteLater();
        _connectionWorker = nullptr;
    });
    
    // Set worker parameters
    _connectionWorker->_ip = _serverIpAddress;
    _connectionWorker->_port = port;
    _connectionWorker->_clientCert = _clientCertFilePath;
    _connectionWorker->_caBundlePath = _caBundleFilePath;
    
    qCDebug(OpenSSLPQCLog) << "[PQC-Connect] Connection parameters set";
    
    // Start the new worker thread
    _connectionWorker->start();
    qCDebug(OpenSSLPQCLog) << "[PQC-Connect] New worker thread started";
    
    qCDebug(OpenSSLPQCLog) << "[PQC-Connect] ⬅️  Main thread returns immediately (UI responsive!)";
    qCDebug(OpenSSLPQCLog) << "";
}

void OpenSSLPQCSettings::disconnectFromServer()
{
    qCDebug(OpenSSLPQCLog) << "";
    qCDebug(OpenSSLPQCLog) << "========== SERVER DISCONNECT REQUEST ==========";
    qCDebug(OpenSSLPQCLog) << "============================================";
    qCDebug(OpenSSLPQCLog) << "";
    
    // Mutex lock for safe cleanup - protects against concurrent access from socket notifiers
    {
        QMutexLocker locker(&_contextMutex);
        
        // Clean up socket notifiers first (must be within mutex protection)
        // This prevents race conditions with onSocketReadyRead/onSocketReadyWrite
        cleanupSocketNotifiers();
        
        // Close PQC TLS connection
        if (_pqcCtx) {
            qCDebug(OpenSSLPQCLog) << "[PQC-Disconnect] Closing PQC TLS connection...";
            pqc_tls_close(_pqcCtx);
            _pqcCtx = nullptr;
        }
    }
    
    qCDebug(OpenSSLPQCLog) << "[PQC-Disconnect] Connection closed";
    
    // Clear buffers (no mutex needed - no concurrent access)
    _readBuffer.clear();
    _writeBuffer.clear();
    
    // Update connection status
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

// ========== PQC TLS Socket Notifiers ==========

void OpenSSLPQCSettings::setupSocketNotifiers()
{
    QMutexLocker locker(&_contextMutex);
    
    if (!_pqcCtx) {
        qCWarning(OpenSSLPQCLog) << "[Notifier-Setup] PQC context is null";
        return;
    }
    
    int fd = pqc_tls_get_fd(_pqcCtx);
    if (fd < 0) {
        qCWarning(OpenSSLPQCLog) << "[Notifier-Setup] Invalid file descriptor";
        return;
    }
    
    // Clean up existing notifiers
    cleanupSocketNotifiers();
    
    // Create read notifier
    _readNotifier = new QSocketNotifier(fd, QSocketNotifier::Read, this);
    connect(_readNotifier, &QSocketNotifier::activated,
            this, &OpenSSLPQCSettings::onSocketReadyRead);
    
    // Create write notifier (disabled initially)
    _writeNotifier = new QSocketNotifier(fd, QSocketNotifier::Write, this);
    connect(_writeNotifier, &QSocketNotifier::activated,
            this, &OpenSSLPQCSettings::onSocketReadyWrite);
    _writeNotifier->setEnabled(false);
    
    qCDebug(OpenSSLPQCLog) << "[Notifier-Setup] Socket notifiers setup complete (fd:" << fd << ")";
}

void OpenSSLPQCSettings::cleanupSocketNotifiers()
{
    if (_readNotifier) {
        disconnect(_readNotifier, nullptr, this, nullptr);
        delete _readNotifier;
        _readNotifier = nullptr;
    }
    if (_writeNotifier) {
        disconnect(_writeNotifier, nullptr, this, nullptr);
        delete _writeNotifier;
        _writeNotifier = nullptr;
    }
    qCDebug(OpenSSLPQCLog) << "[Notifier-Cleanup] Socket notifiers cleaned up";
}

// ========== PQC TLS Data Read/Write ==========

QByteArray OpenSSLPQCSettings::readData(int maxSize)
{
    QMutexLocker locker(&_contextMutex);
    
    if (!_pqcCtx) {
        qCDebug(OpenSSLPQCLog) << "[Read] Not connected";
        return QByteArray();
    }
    
    uint8_t buf[maxSize];
    int encrypted_len = 0;
    
    // Read all available data from socket
    while (true) {
        int n = pqc_tls_read(_pqcCtx, buf, maxSize, NULL, 0, &encrypted_len);
        
        if (n > 0) {
            _readBuffer.append((const char*)buf, n);
            qCDebug(OpenSSLPQCLog) << "[Read] Read" << n << "bytes (encrypted:" << encrypted_len << "bytes)";
        } else if (n == 0) {
            // No data available
            break;
        } else {
            // Error occurred
            qCCritical(OpenSSLPQCLog) << "[Read] Read error, disconnecting";
            locker.unlock();
            disconnectFromServer();
            break;
        }
    }
    
    // Return accumulated data
    QByteArray result = _readBuffer;
    _readBuffer.clear();  // Auto-clear buffer
    
    if (!result.isEmpty()) {
        qCDebug(OpenSSLPQCLog) << "[Read] Returning" << result.size() << "bytes";
    }
    
    return result;
}

int OpenSSLPQCSettings::writeData(const QByteArray& data)
{
    if (data.isEmpty()) {
        return 0;
    }
    
    QMutexLocker locker(&_contextMutex);
    
    if (!_pqcCtx) {
        qCWarning(OpenSSLPQCLog) << "[Write] Not connected, discarding" << data.size() << "bytes";
        return -1;
    }
    
    // Add data to write buffer
    _writeBuffer.append(data);
    qCDebug(OpenSSLPQCLog) << "[Write] Added" << data.size() << "bytes to buffer, total:" << _writeBuffer.size() << "bytes";
    
    // Attempt to send data immediately (loop)
    int totalSent = 0;
    while (_writeBuffer.size() > 0) {
        int n = pqc_tls_write(_pqcCtx, 
                             (const uint8_t*)_writeBuffer.data(),
                             _writeBuffer.size());
        
        if (n > 0) {
            qCDebug(OpenSSLPQCLog) << "[Write] Sent" << n << "bytes (requested:" << _writeBuffer.size() << ")";
            _writeBuffer.remove(0, n);
            totalSent += n;
        } else if (n == 0) {
            // Buffer full or would block - enable write notifier for event loop
            qCDebug(OpenSSLPQCLog) << "[Write] Write would block, enabling notifier for" << _writeBuffer.size() << "remaining bytes";
            if (_writeNotifier) {
                _writeNotifier->setEnabled(true);
            }
            break;
        } else {
            // Error occurred
            qCCritical(OpenSSLPQCLog) << "[Write] Write error, disconnecting";
            locker.unlock();
            disconnectFromServer();
            return -1;
        }
    }
    
    // Return number of bytes still pending in buffer
    int pendingBytes = _writeBuffer.size();
    qCDebug(OpenSSLPQCLog) << "[Write] Write complete. Sent:" << totalSent << "bytes, Pending:" << pendingBytes << "bytes";
    
    return pendingBytes;
}

// ========== PQC TLS Socket Event Handlers ==========

void OpenSSLPQCSettings::onSocketReadyRead()
{
    uint8_t buf[4096];
    uint8_t enc_buf[16400];  // Encrypted packet buffer
    int encrypted_len = 0;
    
    QMutexLocker locker(&_contextMutex);
    
    if (!_pqcCtx) {
        qCWarning(OpenSSLPQCLog) << "[ReadEvent] PQC context is null";
        return;
    }
    
    int n = pqc_tls_read(_pqcCtx, buf, sizeof(buf), enc_buf, sizeof(enc_buf), &encrypted_len);
    
    if (n > 0) {
        qCDebug(OpenSSLPQCLog) << "[ReadEvent] Read" << n << "bytes (encrypted:" << encrypted_len << "bytes)";
        
        // Capture encrypted and decrypted packets
        appendRawPacket(enc_buf, encrypted_len);
        appendDecryptedPacket(buf, n);
        emit rawPacketHexChanged();
        emit decryptedPacketHexChanged();
        
        _readBuffer.append((const char*)buf, n);
        locker.unlock();
        emit dataReceived(_readBuffer);
        
    } else if (n == 0) {
        // No data available (normal)
        qCDebug(OpenSSLPQCLog) << "[ReadEvent] No data available (waiting...)";
        
    } else {
        // Error occurred
        qCCritical(OpenSSLPQCLog) << "[ReadEvent] Read error, disconnecting";
        locker.unlock();
        disconnectFromServer();
    }
}

void OpenSSLPQCSettings::onSocketReadyWrite()
{
    QMutexLocker locker(&_contextMutex);
    
    if (!_pqcCtx) {
        if (_writeNotifier) {
            _writeNotifier->setEnabled(false);
        }
        return;
    }
    
    if (_writeBuffer.isEmpty()) {
        if (_writeNotifier) {
            _writeNotifier->setEnabled(false);
        }
        return;
    }
    
    // Attempt to send all remaining data (loop)
    int totalSent = 0;
    while (_writeBuffer.size() > 0) {
        int n = pqc_tls_write(_pqcCtx, 
                             (const uint8_t*)_writeBuffer.data(),
                             _writeBuffer.size());
        
        if (n > 0) {
            qCDebug(OpenSSLPQCLog) << "[WriteEvent] Sent" << n << "bytes";
            _writeBuffer.remove(0, n);
            totalSent += n;
            
        } else if (n == 0) {
            // Buffer full or would block
            qCDebug(OpenSSLPQCLog) << "[WriteEvent] Write would block, retrying later";
            break;
            
        } else {
            // Error occurred
            qCCritical(OpenSSLPQCLog) << "[WriteEvent] Write error, disconnecting";
            locker.unlock();
            disconnectFromServer();
            return;
        }
    }
    
    // If all data sent, emit signal and disable notifier
    if (_writeBuffer.isEmpty()) {
        if (totalSent > 0) {
            locker.unlock();
            emit dataSent(totalSent);
            locker.relock();
        }
        if (_writeNotifier) {
            _writeNotifier->setEnabled(false);
        }
    }
}

// ========== TLS Log Buffer Management ==========

void OpenSSLPQCSettings::appendTlsLog(const QString& msg)
{
    // Generate timestamp (HH:MM:SS format)
    QTime currentTime = QTime::currentTime();
    QString timestamp = currentTime.toString("hh:mm:ss");
    QString logLine = QString("[%1] %2").arg(timestamp, msg);
    
    // Append to log buffer
    _tlsLogBuffer += logLine + "\n";
    
    // Limit to 50 lines (keep latest lines)
    QStringList lines = _tlsLogBuffer.split('\n', Qt::SkipEmptyParts);
    if (lines.size() > 50) {
        lines = lines.mid(lines.size() - 50);  // Keep latest 50 lines
        _tlsLogBuffer = lines.join('\n') + "\n";
    }
    
    // Emit signal for QML to update
    emit tlsLogBufferChanged();
}

// ========== Raw & Decrypted Packet Hex Management ==========

QString OpenSSLPQCSettings::bytesToHex(const uint8_t* data, int len)
{
    if (!data || len <= 0) {
        return QString();
    }
    
    // Limit to 5KB (max bytes to display)
    const int maxBytes = 5120;  // 5KB
    int displayLen = (len > maxBytes) ? maxBytes : len;
    
    // Convert bytes to hex string with space separation
    QString hexString;
    for (int i = 0; i < displayLen; ++i) {
        if (i > 0) {
            hexString += " ";
        }
        hexString += QString("%1").arg(data[i], 2, 16, QChar('0')).toUpper();
    }
    
    // Append truncation indicator if data was truncated
    if (len > maxBytes) {
        hexString += QString(" ... (truncated, total %1 bytes)").arg(len);
    }
    
    return hexString;
}

void OpenSSLPQCSettings::appendRawPacket(const uint8_t* data, int len)
{
    if (!data || len <= 0) {
        _rawPacketHex = QString();
        return;
    }
    
    // Store latest encrypted packet as hex string
    _rawPacketHex = bytesToHex(data, len);
}

void OpenSSLPQCSettings::appendDecryptedPacket(const uint8_t* data, int len)
{
    if (!data || len <= 0) {
        _decryptedPacketHex = QString();
        return;
    }
    
    // Store latest decrypted packet as hex string
    _decryptedPacketHex = bytesToHex(data, len);
}