// Copyright 2020 CryptoGarage

#ifndef CFD_CORE_SRC_SECP256K1_UTIL_H_
#define CFD_CORE_SRC_SECP256K1_UTIL_H_

#include "cfdcore/cfdcore_key.h"
#include "secp256k1.h"            // NOLINT
#include "secp256k1_extrakeys.h"  // NOLINT

namespace cfd {
namespace core {

using cfd::core::ByteData;
using cfd::core::Pubkey;

/**
 * @brief Parses a cfd-core Pubkey object into a secp256k1_pubkey struct.
 *
 * @param pubkey the pubkey to parse.
 * @return secp256k1_pubkey
 */
secp256k1_pubkey ParsePubkey(const Pubkey& pubkey);

/**
 * @brief Parses a signature contained inside a ByteData object to a
 * secp256k1_ecdsa_signature struct. 
 *
 * @param signature 
 * @return secp256k1_ecdsa_signature
 */
secp256k1_ecdsa_signature ParseSignature(const ByteData& signature);

/**
 * @brief Converts a secp256k1_pubkey struct to a cfd-core Pubkey object.
 *
 * @param pubkey the pubkey struct to convert.
 * @return Pubkey
 */
Pubkey ConvertSecpPubkey(const secp256k1_pubkey& pubkey);

/**
 * @brief Parses a cfd-core Pubkey object to a secp256k1_xonly_pubkey struct.
 *
 * @param pubkey the pubkey to parse.
 * @return secp256k1_xonly_pubkey
 */
secp256k1_xonly_pubkey ParsePubkeyToXOnlyPubkey(const Pubkey& pubkey);

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_SRC_SECP256K1_UTIL_H_
