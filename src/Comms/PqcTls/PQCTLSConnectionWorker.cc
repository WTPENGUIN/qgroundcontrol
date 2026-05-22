/****************************************************************************
 *
 * (c) 2009-2024 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#include "PQCTLSConnectionWorker.h"
#include "OpenSSLPQCSettings.h"
#include "pqc_tls_wrapper.h"
#include "QGCLoggingCategory.h"

#include <QtCore/QThread>

// ========== Constructor / Destructor ==========

PQCTLSConnectionWorker::PQCTLSConnectionWorker(OpenSSLPQCSettings* parent)
    : QThread(parent), _port(0), _parent(parent)
{
    qCDebug(OpenSSLPQCLog) << "[Worker] Constructor: Async connection worker created";
}

PQCTLSConnectionWorker::~PQCTLSConnectionWorker()
{
    if (isRunning()) {
        requestInterruption();
        wait(5000);
    }
    qCDebug(OpenSSLPQCLog) << "[Worker] Destructor: Worker destroyed";
}

// ========== Main Worker Thread Execution ==========

void PQCTLSConnectionWorker::run()
{
    qCDebug(OpenSSLPQCLog) << "";
    qCDebug(OpenSSLPQCLog) << "========== WORKER THREAD STARTED ==========";
    qCDebug(OpenSSLPQCLog) << "Thread ID:" << QThread::currentThreadId();
    qCDebug(OpenSSLPQCLog) << "==========================================";
    qCDebug(OpenSSLPQCLog) << "";
    
    // Validate connection parameters
    if (_ip.isEmpty()) {
        qCCritical(OpenSSLPQCLog) << "[Worker] Error: Server IP is empty";
        emit finished(false, nullptr);
        return;
    }
    
    if (_port <= 0 || _port > 65535) {
        qCCritical(OpenSSLPQCLog) << "[Worker] Error: Invalid port" << _port;
        emit finished(false, nullptr);
        return;
    }
    
    // Initialize PQC TLS library
    qCDebug(OpenSSLPQCLog) << "[Worker] Initializing PQC TLS library...";
    pqc_tls_init_library();
    
    // Attempt PQC TLS connection (BLOCKING - OK in worker thread)
    qCDebug(OpenSSLPQCLog) << "[Worker] Connecting to" << _ip << ":" << _port;
    
    pqc_tls_ctx_t* ctx = pqc_tls_connect(
        _ip.toUtf8().constData(),
        _port,
        _clientCert.toUtf8().constData(),
        _caBundlePath.toUtf8().constData(),
        nullptr,  // logCallback will be set in main thread
        nullptr   // userData
    );
    
    qCDebug(OpenSSLPQCLog) << "";
    
    // Check connection result and emit with context
    if (ctx != nullptr) {
        qCDebug(OpenSSLPQCLog) << "[Worker] ✅ PQC TLS Connection SUCCESS";
        emit finished(true, ctx);
    } else {
        qCCritical(OpenSSLPQCLog) << "[Worker] ❌ PQC TLS Connection FAILED";
        emit finished(false, nullptr);
    }
    
    qCDebug(OpenSSLPQCLog) << "[Worker] Worker thread exiting";
}
