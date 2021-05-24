// Copyright 2020 CryptoGarage

#include "cfdcore/cfdcore_ecdsa_adaptor.h"

#include <cstring>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "secp256k1.h"                // NOLINT
#include "secp256k1_ecdsa_adaptor.h"  // NOLINT
#include "secp256k1_util.h"           // NOLINT
#include "wally_core.h"               // NOLINT

namespace cfd {
namespace core {

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdError;
using cfd::core::CfdException;

// ------------------------
// AdaptorSignature
// ------------------------
AdaptorSignature::AdaptorSignature(const ByteData &data)
    : data_(data) {
  if (data_.GetDataSize() != AdaptorSignature::kAdaptorSignatureSize) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid adaptor signature data.");
  }
}

AdaptorSignature::AdaptorSignature(const std::string &data)
    : AdaptorSignature(ByteData(data)) {}

AdaptorSignature::AdaptorSignature(const AdaptorSignature &signature) {
  data_ = signature.data_;
}

AdaptorSignature &AdaptorSignature::operator=(
    const AdaptorSignature &signature) & {
  if (this != &signature) data_ = signature.data_;
  return *this;
}

AdaptorSignature AdaptorSignature::Encrypt(
    const ByteData256 &msg, const Privkey &sk, const Pubkey &encryption_key) {
  auto ctx = wally_get_secp_context();
  std::vector<uint8_t> adaptor_sig_raw(
      AdaptorSignature::kAdaptorSignatureSize);
  auto adaptor_key = ParsePubkey(encryption_key);
  auto ret = secp256k1_ecdsa_adaptor_encrypt(
      ctx, adaptor_sig_raw.data(), sk.GetData().GetBytes().data(),
      &adaptor_key, msg.GetData().GetBytes().data(), nullptr, nullptr);
  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not create adaptor signature.");
  }

  return AdaptorSignature(adaptor_sig_raw);
}

ByteData AdaptorSignature::Decrypt(const Privkey &sk) const {
  if (!IsValid()) {
    throw CfdException(
        CfdError::kCfdIllegalStateError, "Invalid adaptor signature.");
  }
  auto ctx = wally_get_secp_context();
  secp256k1_ecdsa_signature secp_signature;
  auto ret = secp256k1_ecdsa_adaptor_decrypt(
      ctx, &secp_signature, sk.GetData().GetBytes().data(),
      data_.GetBytes().data());

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not adapt signature.");
  }

  std::vector<uint8_t> signature(64);
  secp256k1_ecdsa_signature_serialize_compact(
      ctx, signature.data(), &secp_signature);

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not serialize signature.");
  }
  return ByteData(signature);
}

Privkey AdaptorSignature::Recover(
    const ByteData &signature, const Pubkey &encryption_key) const {
  if (!IsValid()) {
    throw CfdException(
        CfdError::kCfdIllegalStateError, "Invalid adaptor signature.");
  }
  auto ctx = wally_get_secp_context();
  std::vector<uint8_t> secret(Privkey::kPrivkeySize);
  auto secp_sig = ParseSignature(signature);
  auto secp_adaptor = ParsePubkey(encryption_key);
  auto ret = secp256k1_ecdsa_adaptor_recover(
      ctx, secret.data(), &secp_sig, data_.GetBytes().data(), &secp_adaptor);

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not extract secret.");
  }

  return Privkey(ByteData(secret));
}

bool AdaptorSignature::Verify(
    const ByteData256 &msg, const Pubkey &pubkey,
    const Pubkey &encryption_key) const {
  if (!IsValid()) {
    throw CfdException(
        CfdError::kCfdIllegalStateError, "Invalid adaptor signature.");
  }
  auto ctx = wally_get_secp_context();
  auto secp_pubkey = ParsePubkey(pubkey);
  auto secp_adaptor = ParsePubkey(encryption_key);
  return secp256k1_ecdsa_adaptor_verify(
             ctx, data_.GetBytes().data(), &secp_pubkey, msg.GetBytes().data(),
             &secp_adaptor) == 1;
}

ByteData AdaptorSignature::GetData() const { return data_; }

bool AdaptorSignature::IsValid() const {
  return data_.GetDataSize() == AdaptorSignature::kAdaptorSignatureSize;
}

}  // namespace core
}  // namespace cfd
