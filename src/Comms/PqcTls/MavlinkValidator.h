/****************************************************************************
 *
 * (c) 2009-2024 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QLoggingCategory>
#include <cstdint>
#include "mavlink.h"

Q_DECLARE_LOGGING_CATEGORY(PQCMavlinkValidatorLog)

/// MAVLink Packet Validator for TLS Decrypted Data
/// Location: src/Comms/PqcTls/MavlinkValidator.h
/// 
/// Purpose:
/// Validates and extracts MAVLink packets from fragmented TLS-decrypted data.
/// Handles packet fragmentation across multiple onSocketReadyRead() calls
/// using mavlink_parse_char() byte-by-byte parsing.
/// 
/// Design:
/// - Byte-by-byte state machine (NO explicit buffering)
/// - Fragmentation handled by MAVLink library's internal state
/// - Returns ONE complete packet per call
/// - Stateful: parser state preserved across calls via channel ID
/// 
/// Fragmentation Example:
/// ┌─────────────────────────────────────┐
/// │ Call 1: [PKT1_complete][PKT2_partial]│
/// │ → return: true, outMessage=PKT1      │
/// │ → internal state at PKT2_partial     │
/// ├─────────────────────────────────────┤
/// │ Call 2: [PKT2_completion]            │
/// │ → internal state continues          │
/// │ → return: true, outMessage=PKT2      │
/// └─────────────────────────────────────┘

class MavlinkValidator
{
public:
    /// Constructor
    /// @param channelId MAVLink virtual channel ID (default: 0xFD)
    explicit MavlinkValidator(uint8_t channelId = 0xFD);
    
    /// Destructor
    ~MavlinkValidator();

    /// Validate and extract ONE complete MAVLink packet from decrypted data
    /// 
    /// Processes decryptedData byte-by-byte through mavlink_parse_char().
    /// MAVLink library maintains parsing state internally per channel.
    /// Fragmented packets automatically handled by state machine across calls.
    /// 
    /// Usage:
    /// @code
    /// mavlink_message_t msg = {};
    /// bool hasPacket = validator.validateAndExtractMavlink(decryptedData, msg);
    /// if (hasPacket) {
    ///     // msg contains complete valid packet
    ///     processMessage(msg);
    /// }
    /// // If fragmented: state preserved, next call continues
    /// @endcode
    /// 
    /// @param decryptedData      New TLS-decrypted bytes (may be partial)
    /// @param outMessage         [OUT] Extracted packet (valid only if return=true)
    /// 
    /// @return true              One complete valid packet extracted ✅
    ///         false             No complete packet (incomplete or error)
    bool validateAndExtractMavlink(
        const QByteArray& decryptedData,
        mavlink_message_t& outMessage
    );

    /// Reset channel and clear parsing state
    /// Called on connection termination to prepare for new connection
    void resetChannel();

private:
    // ========== Member Variables ==========
    
    uint8_t m_channelId;              ///< Virtual channel ID
    mavlink_status_t* m_status;       ///< Channel state (from MAVLink library)
    mavlink_message_t* m_message;     ///< Message buffer (from MAVLink library)
};
