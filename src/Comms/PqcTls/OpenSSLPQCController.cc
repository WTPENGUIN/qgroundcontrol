/****************************************************************************
 *
 * (c) 2009-2024 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#include "OpenSSLPQCController.h"
#include "PQCTLSConnectionWorker.h"
#include "QGCLoggingCategory.h"
#include "mavlink.h"

#include <QtQml/QQmlEngine>
#include <QtCore/QDateTime>

QGC_LOGGING_CATEGORY(OpenSSLPQCControllerLog, "qgc.etri.pqc")

// ========== JNI Callback Management ==========
static OpenSSLPQCController* g_pqcSettingsInstance = nullptr;
static QString s_currentImportTarget = "";

// ========== Constructor / Destructor ==========

OpenSSLPQCController::OpenSSLPQCController(QObject *parent) : QObject(parent)
{
    qCDebug(OpenSSLPQCControllerLog) << "OpenSSLPQCController Singleton created";
    
    // Initialize MAVLink Validator
    m_mavlinkValidator = new MavlinkValidator(0xFD);
    qCDebug(OpenSSLPQCControllerLog) << "[Constructor] MAVLink validator initialized";
    
#if defined(Q_OS_ANDROID)
    registerJNICallback();
#endif
}

OpenSSLPQCController::~OpenSSLPQCController()
{
    // Disconnect from server (closes connection and cleans up notifiers)
    disconnectFromServer();
    
    // Clean up MAVLink validator
    if (m_mavlinkValidator) {
        qCDebug(OpenSSLPQCControllerLog) << "[Destructor] Cleaning up MAVLink validator";
        delete m_mavlinkValidator;
        m_mavlinkValidator = nullptr;
    }
    
    // Clean up worker thread
    if (_connectionWorker) {
        qCDebug(OpenSSLPQCControllerLog) << "[Destructor] Cleaning up worker thread...";
        if (_connectionWorker->isRunning()) {
            _connectionWorker->requestInterruption();
            _connectionWorker->wait(5000);
        }
        _connectionWorker->deleteLater();
        _connectionWorker = nullptr;
    }
    
    // Cleanup OpenSSL library
    pqc_tls_cleanup_library();
}

// ========== Server Configuration Setters ==========

void OpenSSLPQCController::setServerIpAddress(const QString& address)
{
    if (_serverIpAddress != address) {
        _serverIpAddress = address;
        qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-Server] IP Address:" << address;
        emit serverIpAddressChanged(address);
    }
}

void OpenSSLPQCController::setServerPortNumber(const QString& port)
{
    if (_serverPortNumber != port) {
        _serverPortNumber = port;
        qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-Server] Port:" << port;
        emit serverPortNumberChanged(port);
    }
}

void OpenSSLPQCController::setServerConnected(bool connected)
{
    if (_serverConnected != connected) {
        _serverConnected = connected;
        qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-Server] Status:" << (connected ? "CONNECTED" : "DISCONNECTED");
        emit serverConnectedChanged(connected);
    }
}

// ========== Routing Configuration Setters ==========

void OpenSSLPQCController::setRoutingPortNumber(const QString& port)
{
    if (_routingPortNumber != port) {
        _routingPortNumber = port;
        qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-Routing] Port:" << port;
        emit routingPortNumberChanged(port);
    }
}

void OpenSSLPQCController::setRoutingConnected(bool connected)
{
    if (_routingConnected != connected) {
        _routingConnected = connected;
        qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-Routing] Status:" << (connected ? "CONNECTED" : "DISCONNECTED");
        emit routingConnectedChanged(connected);
    }
}

// ========== Credential Setters ==========

void OpenSSLPQCController::setCaBundleFilePath(const QString& path)
{
    if (_caBundleFilePath != path) {
        _caBundleFilePath = path;
        qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-Credentials] CA Bundle:" << path;
        emit caBundleFilePathChanged(path);
    }
}

void OpenSSLPQCController::setClientCertFilePath(const QString& path)
{
    if (_clientCertFilePath != path) {
        _clientCertFilePath = path;
        qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-Credentials] Client Cert:" << path;
        emit clientCertFilePathChanged(path);
    }
}

// ========== PQC TLS Logging Callback ==========

void OpenSSLPQCController::logCallback(void* userData, const char* msg)
{
    if (!msg) return;
    QString msgStr = QString::fromUtf8(msg);
    
    // Debug log output
    qCDebug(OpenSSLPQCControllerLog) << "[PQC-C-Library]" << msgStr;
    
    // Filter out read/write logs
    if (msgStr.contains("Sent bytes:", Qt::CaseInsensitive) ||
        msgStr.contains("Received bytes:", Qt::CaseInsensitive) ||
        msgStr.contains("Write:", Qt::CaseInsensitive) ||
        msgStr.contains("Read:", Qt::CaseInsensitive)) {
        return;  // Filtered out
    }
    
    // Append to TLS log buffer
    OpenSSLPQCController* self = static_cast<OpenSSLPQCController*>(userData);
    if (self) {
        self->appendTlsLog(msgStr);
    }
}

// ========== Server Connection Methods ==========

void OpenSSLPQCController::connectToServer()
{
    qCDebug(OpenSSLPQCControllerLog) << "";
    qCDebug(OpenSSLPQCControllerLog) << "========== SERVER CONNECT REQUEST (ASYNC) ==========";
    qCDebug(OpenSSLPQCControllerLog) << "  IP Address      :" << _serverIpAddress;
    qCDebug(OpenSSLPQCControllerLog) << "  Port            :" << _serverPortNumber;
    qCDebug(OpenSSLPQCControllerLog) << "====================================================";
    qCDebug(OpenSSLPQCControllerLog) << "";
    
    // Prevent duplicate connections
    if (_serverConnected || _isConnecting) {
        qCDebug(OpenSSLPQCControllerLog) << "[PQC-Connect] Already connected or connecting";
        return;
    }
    
    // Input validation
    if (_serverIpAddress.isEmpty()) {
        qCCritical(OpenSSLPQCControllerLog) << "[PQC-Connect] Error: Server IP address is empty";
        setServerConnected(false);
        return;
    }
    
    if (_serverPortNumber.isEmpty()) {
        qCCritical(OpenSSLPQCControllerLog) << "[PQC-Connect] Error: Server port number is empty";
        setServerConnected(false);
        return;
    }
    
    if (_caBundleFilePath.isEmpty()) {
        qCCritical(OpenSSLPQCControllerLog) << "[PQC-Connect] Error: CA bundle file path is empty";
        setServerConnected(false);
        return;
    }
    
    if (_clientCertFilePath.isEmpty()) {
        qCCritical(OpenSSLPQCControllerLog) << "[PQC-Connect] Error: Client certificate file path is empty";
        setServerConnected(false);
        return;
    }
    
    // Port number conversion
    bool portOk = false;
    int port = _serverPortNumber.toInt(&portOk);
    if (!portOk || port <= 0 || port > 65535) {
        qCCritical(OpenSSLPQCControllerLog) << "[PQC-Connect] Error: Invalid port number" << _serverPortNumber;
        setServerConnected(false);
        return;
    }
    
    // Update status: starting connection attempt
    setServerConnected(false);
    _isConnecting = true;
    emit connectionStatusChanged("connecting");
    
    qCDebug(OpenSSLPQCControllerLog) << "[PQC-Connect] Starting async connection...";
    
    // Clean up existing worker thread before creating a new one
    // QThread can only be started once, so we must create a new instance for each connection
    if (_connectionWorker) {
        qCDebug(OpenSSLPQCControllerLog) << "[PQC-Connect] Cleaning up previous worker thread...";
        if (_connectionWorker->isRunning()) {
            _connectionWorker->requestInterruption();
            _connectionWorker->wait(5000);
        }
        _connectionWorker->deleteLater();
        _connectionWorker = nullptr;
    }
    
    // Create a new worker thread for this connection attempt
    _connectionWorker = new PQCTLSConnectionWorker(this);
    qCDebug(OpenSSLPQCControllerLog) << "[PQC-Connect] New worker thread created";
    
    // Connect worker finished signal
    connect(_connectionWorker, static_cast<void(PQCTLSConnectionWorker::*)(bool, void*)>(&PQCTLSConnectionWorker::finished),
            this, [this](bool success, void* ctx) {
        if (success && ctx) {
            qCDebug(OpenSSLPQCControllerLog) << "[PQC-Main] ✅ Connection established!";
            _pqcCtx = static_cast<pqc_tls_ctx_t*>(ctx);
            setupSocketNotifiers();
            
            // 방어: ctx 재확인 (race condition 방지)
            if (_pqcCtx) {
                extractAndLogHandshakeInfo(_pqcCtx);  // NEW: 핸드셰이크 정보 추출
            } else {
                qCWarning(OpenSSLPQCControllerLog) << "[PQC-Main] Warning: ctx became NULL after setupSocketNotifiers";
            }
            
            setServerConnected(true);
            emit connectionStatusChanged("connected");
        } else {
            qCCritical(OpenSSLPQCControllerLog) << "[PQC-Main] ❌ Connection failed";
            setServerConnected(false);
            emit connectionStatusChanged("error");
            emit connectionError("Failed to establish PQC TLS connection");
        }
        _isConnecting = false;
    });
    
    connect(_connectionWorker, &QThread::finished, this, [this]() {
        _connectionWorker->deleteLater();
        _connectionWorker = nullptr;
    });
    
    // Set worker parameters
    _connectionWorker->_ip = _serverIpAddress;
    _connectionWorker->_port = port;
    _connectionWorker->_clientCert = _clientCertFilePath;
    _connectionWorker->_caBundlePath = _caBundleFilePath;
    
    qCDebug(OpenSSLPQCControllerLog) << "[PQC-Connect] Connection parameters set";
    
    // Start the new worker thread
    _connectionWorker->start();
    qCDebug(OpenSSLPQCControllerLog) << "[PQC-Connect] New worker thread started";
    
    qCDebug(OpenSSLPQCControllerLog) << "[PQC-Connect] ⬅️  Main thread returns immediately (UI responsive!)";
    qCDebug(OpenSSLPQCControllerLog) << "";
}

void OpenSSLPQCController::disconnectFromServer()
{
    qCDebug(OpenSSLPQCControllerLog) << "";
    qCDebug(OpenSSLPQCControllerLog) << "========== SERVER DISCONNECT REQUEST ==========";
    qCDebug(OpenSSLPQCControllerLog) << "============================================";
    qCDebug(OpenSSLPQCControllerLog) << "";
    
    // Mutex lock for safe cleanup - protects against concurrent access from socket notifiers
    {
        QMutexLocker locker(&_contextMutex);
        
        // Reset MAVLink validator
        if (m_mavlinkValidator) {
            m_mavlinkValidator->resetChannel();
        }
        
        // Clean up socket notifiers first (must be within mutex protection)
        // This prevents race conditions with onSocketReadyRead/onSocketReadyWrite
        cleanupSocketNotifiers();
        
        // Close PQC TLS connection
        if (_pqcCtx) {
            qCDebug(OpenSSLPQCControllerLog) << "[PQC-Disconnect] Closing PQC TLS connection...";
            pqc_tls_close(_pqcCtx);
            _pqcCtx = nullptr;
        }
    }
    
    qCDebug(OpenSSLPQCControllerLog) << "[PQC-Disconnect] Connection closed";
    
    // Clear buffers (no mutex needed - no concurrent access)
    _readBuffer.clear();
    _writeBuffer.clear();
    
    // Clear TLS handshake information and emit signals
    _tlsVersion = "";
    _tlsCipher = "";
    _tlsKeyExchange = "";
    _tlsServerSig = "";
    _tlsServerPubKey = "";
    
    emit tlsVersionChanged(_tlsVersion);
    emit tlsCipherChanged(_tlsCipher);
    emit tlsKeyExchangeChanged(_tlsKeyExchange);
    emit tlsServerSigChanged(_tlsServerSig);
    emit tlsServerPubKeyChanged(_tlsServerPubKey);

    // Reset TLS packet hex viewer
    _rawPacketHex = "Awaiting raw packets...";
    _decryptedPacketHex = "Awaiting decrypted packets...";

    emit rawPacketHexChanged();
    emit decryptedPacketHexChanged();

    // Reset Mavlink viewer
    _mavlinkPacketInfo = "Awaiting Mavlink messages...";

    // Notice TLS disconnect
    QString msgDisStr = QString::fromUtf8("Disconnect from Socket by User.");
    appendTlsLog(msgDisStr);
    
    qCDebug(OpenSSLPQCControllerLog) << "[PQC-Disconnect] TLS handshake information cleared";
    
    // Update connection status
    setServerConnected(false);
}

// ========== Routing Connection Methods ==========

void OpenSSLPQCController::routeConnection()
{
    qCDebug(OpenSSLPQCControllerLog) << "";
    qCDebug(OpenSSLPQCControllerLog) << "========== ROUTING CONNECT REQUEST ==========";
    qCDebug(OpenSSLPQCControllerLog) << "  Port            :" << _routingPortNumber;
    qCDebug(OpenSSLPQCControllerLog) << "==========================================";
    qCDebug(OpenSSLPQCControllerLog) << "";
    
    // TODO: Implement actual routing connection logic
    setRoutingConnected(true);
}

void OpenSSLPQCController::disconnectRouting()
{
    qCDebug(OpenSSLPQCControllerLog) << "";
    qCDebug(OpenSSLPQCControllerLog) << "========== ROUTING DISCONNECT REQUEST ==========";
    qCDebug(OpenSSLPQCControllerLog) << "==============================================";
    qCDebug(OpenSSLPQCControllerLog) << "";
    
    // TODO: Implement actual routing disconnection logic
    setRoutingConnected(false);
}

// ========== File Import Methods (Android) ==========
void OpenSSLPQCController::registerJNICallback()
{
#if defined(Q_OS_ANDROID)
    g_pqcSettingsInstance = this;
    qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File-JNI] Callback registered";
#endif
}
void OpenSSLPQCController::callOpenPQCFileImportDialog(const QString& targetFilename)
{
    qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File] Opening file import dialog for:" << targetFilename;
    
#if defined(Q_OS_ANDROID)
    // 현재 import 대상 저장
    s_currentImportTarget = targetFilename;
    
    QString privateFolderPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    
    QStringList allowedExtensions;
    allowedExtensions << ".crt" << ".pem" << ".cer";
    
    qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File] Private folder:" << privateFolderPath;
    qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File] Allowed extensions:" << allowedExtensions;
    
    AndroidInterface::openPQCFileImportDialog(privateFolderPath, targetFilename, allowedExtensions);
#else
    qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File] Not on Android platform";
#endif
}

// ========== JNI Callback for File Import ==========
extern "C"
{
    JNIEXPORT void JNICALL Java_org_mavlink_qgroundcontrol_QGCActivity_onPQCImportResult(
        JNIEnv* env, jobject obj, jstring filePath)
    {
        if (g_pqcSettingsInstance == nullptr) {
            qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File-JNI] Settings instance is null";
            return;
        }
        
        const QString importedPath = QJniObject(filePath).toString();
        qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File-JNI] Callback received. File path:" << importedPath
                              << "Target:" << s_currentImportTarget;
        
        if (importedPath.isEmpty()) {
            qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File-JNI] Import cancelled or failed";
            return;
        }
        
        // 파일명으로 구분하여 적절한 프로퍼티 업데이트
        if (s_currentImportTarget == "ca_bundle.crt") {
            g_pqcSettingsInstance->setCaBundleFilePath(importedPath);
            qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File] CA Bundle imported:" << importedPath;
        } else if (s_currentImportTarget == "client_cert.pem") {
            g_pqcSettingsInstance->setClientCertFilePath(importedPath);
            qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File] Client Certificate imported:" << importedPath;
        } else {
            qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File] Unknown import target:" << s_currentImportTarget;
        }
    }
}

// ========== File Copy Methods ==========
QString OpenSSLPQCController::getPrivateFolderPath() const
{
    QString path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    return path;
}

QString OpenSSLPQCController::copyAndGetAbsolutePath(const QString& contentUri, const QString& filename)
{
    // 빈 URI 체크 (파일 미선택)
    if (contentUri.isEmpty()) {
        qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File] File not selected (empty URI)";
        return "";
    }
    
    // 프라이빗 폴더 경로
    QString privateFolderPath = getPrivateFolderPath();
    QString targetFilePath = privateFolderPath + "/" + filename;
    
    // Source 파일 열기
    QFile sourceFile(contentUri);
    if (!sourceFile.open(QIODevice::ReadOnly)) {
        qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File] Failed to open source:" << contentUri 
                               << "Error:" << sourceFile.errorString();
        return "";
    }
    
    // Target 파일 쓰기 (자동 덮어쓰기)
    QFile targetFile(targetFilePath);
    if (!targetFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File] Failed to open target:" << targetFilePath 
                               << "Error:" << targetFile.errorString();
        sourceFile.close();
        return "";
    }
    
    // 파일 복사 (스트림 방식 - 메모리 효율)
    qint64 bytesWritten = targetFile.write(sourceFile.readAll());
    sourceFile.close();
    targetFile.close();
    
    // 성공 로깅
    qCDebug(OpenSSLPQCControllerLog) << "[OpenSSL-File] File copied successfully:"
                           << "Source:" << contentUri
                           << "Target:" << targetFilePath
                           << "Size:" << bytesWritten << "bytes";
    
    return targetFilePath;  // 절대 경로 반환
}

// ========== PQC TLS Socket Notifiers ==========

void OpenSSLPQCController::setupSocketNotifiers()
{
    QMutexLocker locker(&_contextMutex);
    
    if (!_pqcCtx) {
        qCWarning(OpenSSLPQCControllerLog) << "[Notifier-Setup] PQC context is null";
        return;
    }
    
    int fd = pqc_tls_get_fd(_pqcCtx);
    if (fd < 0) {
        qCWarning(OpenSSLPQCControllerLog) << "[Notifier-Setup] Invalid file descriptor";
        return;
    }
    
    // Clean up existing notifiers
    cleanupSocketNotifiers();
    
    // Create read notifier
    _readNotifier = new QSocketNotifier(fd, QSocketNotifier::Read, this);
    connect(_readNotifier, &QSocketNotifier::activated,
            this, &OpenSSLPQCController::onSocketReadyRead);
    
    // Create write notifier (disabled initially)
    _writeNotifier = new QSocketNotifier(fd, QSocketNotifier::Write, this);
    connect(_writeNotifier, &QSocketNotifier::activated,
            this, &OpenSSLPQCController::onSocketReadyWrite);
    _writeNotifier->setEnabled(false);
    
    qCDebug(OpenSSLPQCControllerLog) << "[Notifier-Setup] Socket notifiers setup complete (fd:" << fd << ")";
}

void OpenSSLPQCController::cleanupSocketNotifiers()
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
    qCDebug(OpenSSLPQCControllerLog) << "[Notifier-Cleanup] Socket notifiers cleaned up";
}

// ========== PQC TLS Data Read/Write ==========

QByteArray OpenSSLPQCController::readData(int maxSize)
{
    QMutexLocker locker(&_contextMutex);
    
    if (!_pqcCtx) {
        qCDebug(OpenSSLPQCControllerLog) << "[Read] Not connected";
        return QByteArray();
    }
    
    uint8_t buf[maxSize];
    int encrypted_len = 0;
    
    // Read all available data from socket
    while (true) {
        int n = pqc_tls_read(_pqcCtx, buf, maxSize, NULL, 0, &encrypted_len);
        
        if (n > 0) {
            _readBuffer.append((const char*)buf, n);
            qCDebug(OpenSSLPQCControllerLog) << "[Read] Read" << n << "bytes (encrypted:" << encrypted_len << "bytes)";
        } else if (n == 0) {
            // No data available
            break;
        } else {
            // Error occurred
            qCCritical(OpenSSLPQCControllerLog) << "[Read] Read error, disconnecting";
            locker.unlock();
            disconnectFromServer();
            break;
        }
    }
    
    // Return accumulated data
    QByteArray result = _readBuffer;
    _readBuffer.clear();  // Auto-clear buffer
    
    if (!result.isEmpty()) {
        qCDebug(OpenSSLPQCControllerLog) << "[Read] Returning" << result.size() << "bytes";
    }
    
    return result;
}

int OpenSSLPQCController::writeData(const QByteArray& data)
{
    if (data.isEmpty()) {
        return 0;
    }
    
    QMutexLocker locker(&_contextMutex);
    
    if (!_pqcCtx) {
        qCWarning(OpenSSLPQCControllerLog) << "[Write] Not connected, discarding" << data.size() << "bytes";
        return -1;
    }
    
    // Add data to write buffer
    _writeBuffer.append(data);
    qCDebug(OpenSSLPQCControllerLog) << "[Write] Added" << data.size() << "bytes to buffer, total:" << _writeBuffer.size() << "bytes";
    
    // Attempt to send data immediately (loop)
    int totalSent = 0;
    while (_writeBuffer.size() > 0) {
        int n = pqc_tls_write(_pqcCtx, 
                             (const uint8_t*)_writeBuffer.data(),
                             _writeBuffer.size());
        
        if (n > 0) {
            qCDebug(OpenSSLPQCControllerLog) << "[Write] Sent" << n << "bytes (requested:" << _writeBuffer.size() << ")";
            _writeBuffer.remove(0, n);
            totalSent += n;
        } else if (n == 0) {
            // Buffer full or would block - enable write notifier for event loop
            qCDebug(OpenSSLPQCControllerLog) << "[Write] Write would block, enabling notifier for" << _writeBuffer.size() << "remaining bytes";
            if (_writeNotifier) {
                _writeNotifier->setEnabled(true);
            }
            break;
        } else {
            // Error occurred
            qCCritical(OpenSSLPQCControllerLog) << "[Write] Write error, disconnecting";
            locker.unlock();
            disconnectFromServer();
            return -1;
        }
    }
    
    // Return number of bytes still pending in buffer
    int pendingBytes = _writeBuffer.size();
    qCDebug(OpenSSLPQCControllerLog) << "[Write] Write complete. Sent:" << totalSent << "bytes, Pending:" << pendingBytes << "bytes";
    
    return pendingBytes;
}

// ========== PQC TLS Socket Event Handlers ==========

void OpenSSLPQCController::onSocketReadyRead()
{
    uint8_t buf[4096];
    uint8_t enc_buf[16400];  // Encrypted packet buffer
    int encrypted_len = 0;
    
    QMutexLocker locker(&_contextMutex);
    
    if (!_pqcCtx) {
        qCWarning(OpenSSLPQCControllerLog) << "[ReadEvent] PQC context is null";
        return;
    }
    
    int n = pqc_tls_read(_pqcCtx, buf, sizeof(buf), enc_buf, sizeof(enc_buf), &encrypted_len);
    
    if (n > 0) {
        qCDebug(OpenSSLPQCControllerLog) << "[ReadEvent] Read" << n << "bytes (encrypted:" << encrypted_len << "bytes)";
        
        // Capture encrypted and decrypted packets
        appendRawPacket(enc_buf, encrypted_len);
        appendDecryptedPacket(buf, n);
        emit rawPacketHexChanged();
        emit decryptedPacketHexChanged();
        
        // MAVLink Validation
         if (m_mavlinkValidator) {
             QByteArray decryptedData((const char*)buf, n);
             mavlink_message_t mavlinkMsg = {};
             
             // Validate and extract ONE complete packet
             // Parser state preserved across calls for fragmentation handling
             if (m_mavlinkValidator->validateAndExtractMavlink(decryptedData, mavlinkMsg)) {
                 // ✅ One complete valid MAVLink packet extracted
                 qCDebug(OpenSSLPQCControllerLog)
                     << "[ReadEvent] ✅ Valid MAVLink message"
                     << "MsgID:" << mavlinkMsg.msgid
                     << "Seq:" << mavlinkMsg.seq
                     << "SysID:" << mavlinkMsg.sysid
                     << "CompID:" << mavlinkMsg.compid;
                 
                 // Call slot to handle packet info update
                 onMavlinkPacketValidated(mavlinkMsg);
                 
                 // Multiple packets: next onSocketReadyRead() call will extract them
             }
         }
        
        _readBuffer.append((const char*)buf, n);
        locker.unlock();
        emit dataReceived(_readBuffer);
        
    } else if (n == 0) {
        // No data available (normal)
        qCDebug(OpenSSLPQCControllerLog) << "[ReadEvent] No data available (waiting...)";
        
    } else {
        // Error occurred
        qCCritical(OpenSSLPQCControllerLog) << "[ReadEvent] Read error, disconnecting";
        locker.unlock();
        disconnectFromServer();
    }
}

void OpenSSLPQCController::onSocketReadyWrite()
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
            qCDebug(OpenSSLPQCControllerLog) << "[WriteEvent] Sent" << n << "bytes";
            _writeBuffer.remove(0, n);
            totalSent += n;
            
        } else if (n == 0) {
            // Buffer full or would block
            qCDebug(OpenSSLPQCControllerLog) << "[WriteEvent] Write would block, retrying later";
            break;
            
        } else {
            // Error occurred
            qCCritical(OpenSSLPQCControllerLog) << "[WriteEvent] Write error, disconnecting";
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

void OpenSSLPQCController::appendTlsLog(const QString& msg)
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

QString OpenSSLPQCController::bytesToHex(const uint8_t* data, int len)
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

void OpenSSLPQCController::appendRawPacket(const uint8_t* data, int len)
{
    if (!data || len <= 0) {
        _rawPacketHex = QString();
        return;
    }
    
    // Store latest encrypted packet as hex string
    _rawPacketHex = bytesToHex(data, len);
}

void OpenSSLPQCController::appendDecryptedPacket(const uint8_t* data, int len)
{
    if (!data || len <= 0) {
        _decryptedPacketHex = QString();
        return;
    }
    
    // Store latest decrypted packet as hex string
    _decryptedPacketHex = bytesToHex(data, len);
}

// ===== TLS HandShake Information Extraction =====

void OpenSSLPQCController::extractAndLogHandshakeInfo(pqc_tls_ctx_t* ctx)
{
    // NULL 체크
    if (!ctx) {
        qCWarning(OpenSSLPQCControllerLog) << "[HandShake-Info] Error: ctx is NULL";
        _tlsVersion = "ERROR";
        _tlsCipher = "ERROR";
        _tlsKeyExchange = "ERROR";
        _tlsServerSig = "ERROR";
        _tlsServerPubKey = "ERROR";
        emit tlsVersionChanged(_tlsVersion);
        emit tlsCipherChanged(_tlsCipher);
        emit tlsKeyExchangeChanged(_tlsKeyExchange);
        emit tlsServerSigChanged(_tlsServerSig);
        emit tlsServerPubKeyChanged(_tlsServerPubKey);
        return;
    }
    
    qCDebug(OpenSSLPQCControllerLog) << "[HandShake-Info] Extracting TLS handshake information...";
    
    // Wrapper 함수 호출
    pqc_tls_handshake_info_t info = pqc_tls_get_handshake_info(ctx);
    
    // 유효성 체크
    if (!info.valid) {
        qCWarning(OpenSSLPQCControllerLog) << "[HandShake-Info] Error: Failed to extract handshake info";
        _tlsVersion = "ERROR";
        _tlsCipher = "ERROR";
        _tlsKeyExchange = "ERROR";
        _tlsServerSig = "ERROR";
        _tlsServerPubKey = "ERROR";
        emit tlsVersionChanged(_tlsVersion);
        emit tlsCipherChanged(_tlsCipher);
        emit tlsKeyExchangeChanged(_tlsKeyExchange);
        emit tlsServerSigChanged(_tlsServerSig);
        emit tlsServerPubKeyChanged(_tlsServerPubKey);
        return;
    }
    
    // 각 필드 개별 추출 및 업데이트
    _tlsVersion = QString::fromUtf8(info.version.version);
    _tlsCipher = QString::fromUtf8(info.cipher.name);
    _tlsKeyExchange = QString::fromUtf8(info.key_exchange.group_name);
    _tlsServerSig = QString::fromUtf8(info.signature.algorithm);
    _tlsServerPubKey = QString::fromUtf8(info.public_key.algorithm);
    
    // 각 필드에 추가 정보 포함
    if (info.cipher.bits > 0) {
        _tlsCipher += QString(" (%1 bits)").arg(info.cipher.bits);
    }
    
    if (info.key_exchange.nid > 0) {
        _tlsKeyExchange += QString(" (NID: %1)").arg(info.key_exchange.nid);
    }
    
    if (strlen(info.signature.long_name) > 0) {
        _tlsServerSig += QString(" (%1)").arg(QString::fromUtf8(info.signature.long_name));
    }
    
    if (info.public_key.key_bits > 0) {
        _tlsServerPubKey += QString(" (%1 bits)").arg(info.public_key.key_bits);
    } else if (strlen(info.public_key.long_name) > 0) {
        _tlsServerPubKey += QString(" (%1)").arg(QString::fromUtf8(info.public_key.long_name));
    }
    
    // Signal 방출
    emit tlsVersionChanged(_tlsVersion);
    emit tlsCipherChanged(_tlsCipher);
    emit tlsKeyExchangeChanged(_tlsKeyExchange);
    emit tlsServerSigChanged(_tlsServerSig);
    emit tlsServerPubKeyChanged(_tlsServerPubKey);
    
    qCDebug(OpenSSLPQCControllerLog) << "[HandShake-Info] Extraction complete"
                           << "Version:" << _tlsVersion
                           << "Cipher:" << _tlsCipher
                           << "KeyExchange:" << _tlsKeyExchange
                           << "ServerSig:" << _tlsServerSig
                           << "ServerPubKey:" << _tlsServerPubKey;
}

// ========== MAVLink Message Handling ==========

QString OpenSSLPQCController::getMavlinkMessageName(uint32_t msgId)
{
    // Use MAVLINK_MESSAGE_NAMES macro which provides { "NAME", msgid } pairs
    // This is defined in the MAVLink library's common.h
    
    #define MAVLINK_MESSAGE_NAMES_ARRAY MAVLINK_MESSAGE_NAMES
    
    // MAVLINK_MESSAGE_NAMES is a compound literal with structure: { "NAME", msgid }
    // We need to iterate through and find the matching msgid
    
    const struct {
        const char* name;
        uint32_t msgid;
    } names[] = MAVLINK_MESSAGE_NAMES;
    
    static const size_t namesCount = sizeof(names) / sizeof(names[0]);
    
    for (size_t i = 0; i < namesCount; ++i) {
        if (names[i].msgid == msgId) {
            return QString::fromLatin1(names[i].name);
        }
    }
    
    return "";  // Return empty string if message not found
}

void OpenSSLPQCController::onMavlinkPacketValidated(const mavlink_message_t& msg)
{
    // Get message name from ID
    QString msgName = getMavlinkMessageName(msg.msgid);
    
    // Format message ID string
    QString msgIdStr;
    if (msgName.isEmpty()) {
        msgIdStr = QString::number(msg.msgid);
    } else {
        msgIdStr = QString::number(msg.msgid) + " (" + msgName + ")";
    }
    
    // Get current system time in HH:mm:ss.zzz format
    QString timeStr = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
    
    // Format packet information
    _mavlinkPacketInfo = QString(
        "MsgID: %1\n"
        "Seq: %2 | SysID: %3 | CompID: %4\n"
        "Timestamp: %5"
    )
    .arg(msgIdStr)
    .arg(msg.seq)
    .arg(msg.sysid)
    .arg(msg.compid)
    .arg(timeStr);
    
    // Emit signal to update QML
    emit mavlinkPacketInfoUpdated(_mavlinkPacketInfo);
    
    qCDebug(OpenSSLPQCControllerLog)
        << "[MAVLink] Packet info updated:"
        << "MsgID:" << msg.msgid
        << "Name:" << msgName
        << "Seq:" << msg.seq
        << "Time:" << timeStr;
}
