/****************************************************************************
 *
 * (c) 2009-2024 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#pragma once

#include <QtCore/QThread>
#include <QtCore/QString>

// Forward declaration
extern "C" {
typedef struct pqc_tls_ctx_t pqc_tls_ctx_t;
}

class OpenSSLPQCSettings;

/// Worker thread for async PQC TLS connection
/// Prevents UI thread blocking during TLS handshake
class PQCTLSConnectionWorker : public QThread
{
    Q_OBJECT
    
public:
    explicit PQCTLSConnectionWorker(OpenSSLPQCSettings* parent);
    ~PQCTLSConnectionWorker();
    
    /// Main thread execution (blocking operations OK here)
    void run() override;
    
    // Connection parameters
    QString _ip;
    int _port = 0;
    QString _clientCert;
    QString _caBundlePath;
    
signals:
    /// Emitted when connection attempt completes with context pointer
    void finished(bool success, void* ctx);
    
private:
    OpenSSLPQCSettings* _parent;
};
