// Copyright 2020 CryptoGarage

#include "cfdcore/cfdcore_schnorrsig.h"

#include <cstring>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "secp256k1.h"             // NOLINT
#include "secp256k1_schnorrsig.h"  // NOLINT
#include "secp256k1_util.h"        // NOLINT
#include "wally_core.h"            // NOLINT

namespace cfd {
namespace core {

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdError;
using cfd::core::CfdException;

SchnorrSignature::SchnorrSignature(const ByteData &data) : data_(data) {
  if ((data_.GetDataSize()) != SchnorrSignature::kSchnorrSignatureSize) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Schnorr signature data.");
  }
}

SchnorrSignature::SchnorrSignature(const std::string &data)
    : SchnorrSignature(ByteData(data)) {}

ByteData SchnorrSignature::GetData() const { return data_; }

SchnorrNonce SchnorrSignature::GetNonce() const {
  auto bytes = data_.GetBytes();
  return SchnorrNonce(ByteData(std::vector<uint8_t>(
      bytes.begin(), bytes.begin() + SchnorrNonce::kSchnorrNonceSize)));
}

Privkey SchnorrSignature::GetPrivkey() const {
  auto bytes = data_.GetBytes();
  auto start = bytes.begin() + SchnorrNonce::kSchnorrNonceSize;
  auto end = start + Privkey::kPrivkeySize;
  return Privkey(ByteData(std::vector<uint8_t>(start, end)));
}

SchnorrNonce::SchnorrNonce(const ByteData &data) : data_(data) {
  if ((data_.GetDataSize()) != SchnorrNonce::kSchnorrNonceSize) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Schnorr nonce data.");
  }
}

SchnorrNonce::SchnorrNonce(const std::string &data)
    : SchnorrNonce(ByteData(data)) {}

ByteData SchnorrNonce::GetData() const { return data_; }

/**
 * @brief A function that simply copies the data into the nonce.
 *
 * @param nonce32 the nonce
 * @param msg32 unused
 * @param key32 unused
 * @param algo16 unused
 * @param xonly_pk32 unused
 * @param data the data (actually the nonce to use)
 * @return int always returns 1
 */
int ConstantNonceFunction(
    unsigned char *nonce32, const unsigned char *msg32,
    const unsigned char *key32, const unsigned char *algo16,
    const unsigned char *xonly_pk32, void *data) {
  (void)msg32;
  (void)key32;
  (void)algo16;
  (void)xonly_pk32;
  std::memcpy(nonce32, (const unsigned char *)data, 32);
  return 1;
}

/**
 * @brief Constant nonce function instance to be passed to secp256k1.
 * 
 */
const secp256k1_nonce_function_hardened ConstantNonce = ConstantNonceFunction;

/**
 * @brief Private function to both create a schnorr signature using the default
 * bip340 nonce function (and passing aux_rand as ndata) or using the constant
 * nonce function (and passing the nonce as ndata)
 *
 * @param msg the message to sign
 * @param sk the private key to use
 * @param nonce_fn the nonce function to use (if null uses bip 340 nonce function)
 * @param ndata the ndata to pass
 * @return SchnorrSignature the generated signature
 */
SchnorrSignature SignCommon(
    const ByteData256 &msg, const Privkey &sk,
    const secp256k1_nonce_function_hardened *nonce_fn, const ByteData ndata) {
  auto ctx = wally_get_secp_context();
  secp256k1_keypair keypair;
  auto ret =
      secp256k1_keypair_create(ctx, &keypair, sk.GetData().GetBytes().data());

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not create keypair.");
  }

  secp256k1_nonce_function_hardened nfn =
      nonce_fn == nullptr ? nullptr : *nonce_fn;

  std::vector<uint8_t> raw_sig(SchnorrSignature::kSchnorrSignatureSize);

  ret = secp256k1_schnorrsig_sign(
      ctx, raw_sig.data(), msg.GetBytes().data(), &keypair, nfn,
      ndata.GetBytes().data());

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not create Schnorr signature.");
  }

  return SchnorrSignature(raw_sig);
}

SchnorrSignature SchnorrUtil::Sign(
    const ByteData256 &msg, const Privkey &sk, const ByteData256 &aux_rand) {
  return SignCommon(msg, sk, nullptr, aux_rand.GetData());
}

SchnorrSignature SchnorrUtil::SignWithNonce(
    const ByteData256 &msg, const Privkey &sk, const Privkey &nonce) {
  return SignCommon(msg, sk, &ConstantNonce, nonce.GetData());
}

Pubkey SchnorrUtil::ComputeSigPoint(
    const ByteData256 &msg, const SchnorrNonce &nonce, const Pubkey &pubkey) {
  auto ctx = wally_get_secp_context();
  secp256k1_xonly_pubkey xonly_pubkey = ParsePubkeyToXOnlyPubkey(pubkey);

  secp256k1_pubkey secp_sigpoint;
  secp256k1_xonly_pubkey secp_nonce;

  auto nonce_bytes = nonce.GetData().GetBytes();
  size_t copy_size = sizeof(secp_nonce.data);
  if (copy_size > nonce_bytes.size()) copy_size = nonce_bytes.size();
  memset(&secp_nonce, 0, sizeof(secp_nonce));
  memcpy(secp_nonce.data, nonce_bytes.data(), copy_size);

  auto ret = secp256k1_schnorrsig_compute_sigpoint(
      ctx, &secp_sigpoint, msg.GetBytes().data(), &secp_nonce, &xonly_pubkey);
  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not compute sigpoint");
  }

  return ConvertSecpPubkey(secp_sigpoint);
}

bool SchnorrUtil::Verify(
    const SchnorrSignature &signature, const ByteData256 &msg,
    const Pubkey &pubkey) {
  auto ctx = wally_get_secp_context();
  secp256k1_xonly_pubkey xonly_pubkey = ParsePubkeyToXOnlyPubkey(pubkey);
  return 1 == secp256k1_schnorrsig_verify(
                  ctx, signature.GetData().GetBytes().data(),
                  msg.GetBytes().data(), &xonly_pubkey);
}

}  // namespace core
}  // namespace cfd
