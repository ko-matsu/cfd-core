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
    : data_(data), sig_data_() {
  if (data_.GetDataSize() == AdaptorSignature::kAdaptorSignatureMinimumSize) {
    std::vector<uint8_t> sig_arr(AdaptorSignature::kAdaptorSignatureSize);
    auto sig_arr_ptr = sig_arr.data();
    memset(sig_arr_ptr, 0, sig_arr.size());

    auto sig_data = data.GetBytes();
    auto sig_ptr = sig_data.data();
    memcpy(&sig_arr_ptr[0], &sig_ptr[0], 33);
    memcpy(&sig_arr_ptr[66], &sig_ptr[33], 32);
    sig_data_ = ByteData(sig_arr);
  } else if (data_.GetDataSize() != AdaptorSignature::kAdaptorSignatureSize) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid adaptor signature data.");
  }
}

AdaptorSignature::AdaptorSignature(const std::string &data)
    : AdaptorSignature(ByteData(data)) {}

AdaptorSignature::AdaptorSignature(
    const AdaptorSignature &signature, const AdaptorProof &proof)
    : data_(), sig_data_() {
  if ((!signature.IsValid()) || (!proof.IsValid())) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Invalid adaptor signature or proof.");
  }

  if (signature.data_.GetDataSize() ==
      AdaptorSignature::kAdaptorSignatureSize) {
    data_ = signature.data_;
  } else {
    std::vector<uint8_t> sig_arr(AdaptorSignature::kAdaptorSignatureSize);
    auto sig_arr_ptr = sig_arr.data();

    std::vector<uint8_t> sig_data = signature.GetData().GetBytes();
    std::vector<uint8_t> proof_data = proof.GetData().GetBytes();

    auto sig_ptr = sig_data.data();
    auto proof_ptr = proof_data.data();
    memcpy(&sig_arr_ptr[0], &sig_ptr[0], 33);
    memcpy(&sig_arr_ptr[33], &proof_ptr[0], 33);
    memcpy(&sig_arr_ptr[66], &sig_ptr[33], 32);
    memcpy(&sig_arr_ptr[98], &proof_ptr[33], 32);
    memcpy(&sig_arr_ptr[130], &proof_ptr[65], 32);
    data_ = ByteData(sig_arr);
  }
}

AdaptorSignature::AdaptorSignature(const AdaptorSignature &signature) {
  data_ = signature.data_;
  sig_data_ = signature.sig_data_;
}

AdaptorSignature &AdaptorSignature::operator=(
    const AdaptorSignature &signature) & {
  if (this != &signature) {
    data_ = signature.data_;
    sig_data_ = signature.sig_data_;
  }
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
  auto &data = sig_data_.IsEmpty() ? data_ : sig_data_;
  auto ret = secp256k1_ecdsa_adaptor_decrypt(
      ctx, &secp_signature, sk.GetData().GetBytes().data(),
      data.GetBytes().data());

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
  auto &data = sig_data_.IsEmpty() ? data_ : sig_data_;
  auto ret = secp256k1_ecdsa_adaptor_recover(
      ctx, secret.data(), &secp_sig, data.GetBytes().data(), &secp_adaptor);

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
  auto &data = sig_data_.IsEmpty() ? data_ : sig_data_;
  return secp256k1_ecdsa_adaptor_verify(
             ctx, data.GetBytes().data(), &secp_pubkey, msg.GetBytes().data(),
             &secp_adaptor) == 1;
}

ByteData AdaptorSignature::GetData() const { return data_; }

ByteData AdaptorSignature::GetFullyData() const {
  return sig_data_.IsEmpty() ? data_ : sig_data_;
}

bool AdaptorSignature::IsValid() const {
  if ((data_.GetDataSize() == AdaptorSignature::kAdaptorSignatureSize) &&
      (sig_data_.IsEmpty())) {
    return true;
  } else if (
      (sig_data_.GetDataSize() == AdaptorSignature::kAdaptorSignatureSize) &&
      (data_.GetDataSize() ==
       AdaptorSignature::kAdaptorSignatureMinimumSize)) {
    return true;
  } else {
    return false;
  }
}

// ------------------------
// AdaptorProof
// ------------------------
AdaptorProof::AdaptorProof(const ByteData &data) : data_(data) {
  if ((data_.GetDataSize()) != AdaptorProof::kAdaptorProofSize) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid adaptor proof data.");
  }
}

ByteData AdaptorProof::GetData() const { return data_; }

AdaptorProof::AdaptorProof(const std::string &data)
    : AdaptorProof(ByteData(data)) {}

bool AdaptorProof::IsValid() const {
  return (data_.GetDataSize() == AdaptorProof::kAdaptorProofSize);
}

// ------------------------
// AdaptorUtil
// ------------------------
AdaptorPair AdaptorUtil::Sign(
    const ByteData256 &msg, const Privkey &sk, const Pubkey &encryption_key) {
  auto sig = AdaptorSignature::Encrypt(msg, sk, encryption_key);
  auto sig_arr = sig.GetData().GetBytes();
  auto sig_arr_ptr = sig_arr.data();

  std::vector<uint8_t> sig_data(
      AdaptorSignature::kAdaptorSignatureMinimumSize);
  std::vector<uint8_t> proof_data(AdaptorProof::kAdaptorProofSize);

  auto sig_ptr = sig_data.data();
  auto proof_ptr = proof_data.data();
  memcpy(&sig_ptr[0], &sig_arr_ptr[0], 33);
  memcpy(&proof_ptr[0], &sig_arr_ptr[33], 33);
  memcpy(&sig_ptr[33], &sig_arr_ptr[66], 32);
  memcpy(&proof_ptr[33], &sig_arr_ptr[98], 32);
  memcpy(&proof_ptr[65], &sig_arr_ptr[130], 32);

  AdaptorPair pair;
  pair.signature = AdaptorSignature(ByteData(sig_data));
  pair.proof = AdaptorProof(ByteData(proof_data));
  return pair;
}

ByteData AdaptorUtil::Adapt(
    const AdaptorSignature &adaptor_signature, const Privkey &sk) {
  return adaptor_signature.Decrypt(sk);
}

Privkey AdaptorUtil::ExtractSecret(
    const AdaptorSignature &adaptor_sig, const ByteData &signature,
    const Pubkey &encryption_key) {
  return adaptor_sig.Recover(signature, encryption_key);
}

bool AdaptorUtil::Verify(
    const AdaptorSignature &adaptor_sig, const AdaptorProof &proof,
    const Pubkey &encryption_key, const ByteData256 &msg,
    const Pubkey &pubkey) {
  auto new_sig = AdaptorSignature(adaptor_sig, proof);
  return new_sig.Verify(msg, pubkey, encryption_key);
}

}  // namespace core
}  // namespace cfd
