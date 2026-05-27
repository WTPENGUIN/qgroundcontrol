/****************************************************************************
 *
 * (c) 2009-2024 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#include "PQCTLSConnectionWorker.h"
#include "OpenSSLPQCController.h"
#include "pqc_tls_wrapper.h"
#include "QGCLoggingCategory.h"

#include <QtCore/QThread>

// ========== Constructor / Destructor ==========

PQCTLSConnectionWorker::PQCTLSConnectionWorker(OpenSSLPQCController* parent)
    : QThread(parent), _port(0), _parent(parent)
{
    qCDebug(OpenSSLPQCControllerLog) << "[Worker] Constructor: Async connection worker created";
}

PQCTLSConnectionWorker::~PQCTLSConnectionWorker()
{
    if (isRunning()) {
        requestInterruption();
        wait(5000);
    }
    qCDebug(OpenSSLPQCControllerLog) << "[Worker] Destructor: Worker destroyed";
}

// ========== Main Worker Thread Execution ==========

void PQCTLSConnectionWorker::run()
{
    qCDebug(OpenSSLPQCControllerLog) << "";
    qCDebug(OpenSSLPQCControllerLog) << "========== WORKER THREAD STARTED ==========";
    qCDebug(OpenSSLPQCControllerLog) << "Thread ID:" << QThread::currentThreadId();
    qCDebug(OpenSSLPQCControllerLog) << "==========================================";
    qCDebug(OpenSSLPQCControllerLog) << "";
    
    // Validate connection parameters
    if (_ip.isEmpty()) {
        qCCritical(OpenSSLPQCControllerLog) << "[Worker] Error: Server IP is empty";
        emit finished(false, nullptr);
        return;
    }
    
    if (_port <= 0 || _port > 65535) {
        qCCritical(OpenSSLPQCControllerLog) << "[Worker] Error: Invalid port" << _port;
        emit finished(false, nullptr);
        return;
    }
    
    // Initialize PQC TLS library
    qCDebug(OpenSSLPQCControllerLog) << "[Worker] Initializing PQC TLS library...";
    pqc_tls_init_library();
    
    // Attempt PQC TLS connection (BLOCKING - OK in worker thread)
    qCDebug(OpenSSLPQCControllerLog) << "[Worker] Connecting to" << _ip << ":" << _port;
    
    pqc_tls_ctx_t* ctx = pqc_tls_connect(
        _ip.toUtf8().constData(),
        _port,
        _clientCert.toUtf8().constData(),
        _caBundlePath.toUtf8().constData(),
        &OpenSSLPQCController::logCallback,  // Capture handshake logs
        _parent  // userData (this pointer)
    );
    
    qCDebug(OpenSSLPQCControllerLog) << "";
    
    // Check connection result and emit with context
    if (ctx != nullptr) {
        qCDebug(OpenSSLPQCControllerLog) << "[Worker] ✅ PQC TLS Connection SUCCESS";
        emit finished(true, ctx);
    } else {
        qCCritical(OpenSSLPQCControllerLog) << "[Worker] ❌ PQC TLS Connection FAILED";
        emit finished(false, nullptr);
    }
    
    qCDebug(OpenSSLPQCControllerLog) << "[Worker] Worker thread exiting";
}
