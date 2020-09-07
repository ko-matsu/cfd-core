// Copyright 2020 CryptoGarage
#include <string>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"

#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_SCHNORRSIG_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_SCHNORRSIG_H_

namespace cfd {
namespace core {

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::Privkey;
using cfd::core::Pubkey;

/**
 * @brief A Schnorr nonce.
 *
 */
class CFD_CORE_EXPORT SchnorrNonce {
 public:
  /**
  * @brief Size of a Schnorr nonce.
  *
  */
  static constexpr uint32_t kSchnorrNonceSize = 32;

  /**
   * @brief Construct a new Schnorr Nonce object from ByteData
   *
   * @param data the data representing the adaptor nonce
   */
  explicit SchnorrNonce(const ByteData &data);
  /**
   * @brief Construct a new Schnorr Nonce object from a string
   *
   * @param data the data representing the adaptor nonce
   */
  explicit SchnorrNonce(const std::string &data);

  /**
   * @brief Get the underlying ByteData object
   *
   * @return ByteData
   */
  ByteData GetData() const;

 private:
  /**
   * @brief The underlying data
   *
   */
  ByteData data_;
};

/**
 * @brief A Schnorr signature.
 *
 */
class CFD_CORE_EXPORT SchnorrSignature {
 public:
  /**
  * @brief Size of a Schnorr signature.
  *
  */
  static constexpr uint32_t kSchnorrSignatureSize = 64;

  /**
   * @brief Construct a new Schnorr Signature object from ByteData
   *
   * @param data the data representing the adaptor signature
   */
  explicit SchnorrSignature(const ByteData &data);

  /**
   * @brief Construct a new Schnorr Signature object from a string
   *
   * @param data the data representing the adaptor signature
   */
  explicit SchnorrSignature(const std::string &data);

  /**
   * @brief Get the underlying ByteData object
   *
   * @return ByteData
   */
  ByteData GetData() const;

  /**
   * @brief Return the nonce part of the signature.
   *
   * @return
   */
  SchnorrNonce GetNonce() const;

  /**
   * @brief Returns the second part of the signature as a Privkey instance.
   *
   * @return Privkey
   */
  Privkey GetPrivkey() const;

 private:
  /**
   * @brief The underlying data
   *
   */
  ByteData data_;
};

/**
 * @brief This class contain utility functions to work with schnorr signatures.
 */
class CFD_CORE_EXPORT SchnorrUtil {
 public:
  /**
   * @brief Create a schnorr signature over the given message using the given
   * private key and auxiliary random data.
   *
   * @param msg the message to create the signature for.
   * @param sk the secret key to create the signature with.
   * @param aux_rand the auxiliary random data used to create the nonce.
   * @return SchnorrSignature
   */
  static SchnorrSignature Sign(
      const ByteData256 &msg, const Privkey &sk, const ByteData256 &aux_rand);

  /**
   * @brief Create a schnorr signature over the given message using the given
   * private key.
   *
   * @param msg the message to create the signature for.
   * @param sk the secret key to create the signature with.
   * @param nonce the nonce to use to create the signature.
   * @return SchnorrSignature
   */
  static SchnorrSignature SignWithNonce(
      const ByteData256 &msg, const Privkey &sk, const Privkey &nonce);

  /**
   * @brief Compute a signature point for a Schnorr signature.
   *
   * @param msg the message that will be signed.
   * @param nonce the public component of the nonce that will be used.
   * @param pubkey the public key for which the signature will be valid.
   * @return Pubkey the signature point.
   */
  static Pubkey ComputeSigPoint(
      const ByteData256 &msg, const SchnorrNonce &nonce, const Pubkey &pubkey);

  /**
   * @brief Verify a Schnorr signature.
   *
   * @param signature the signature to verify.
   * @param msg the message to verify the signature against.
   * @param pubkey the public key to verify the signature against.
   * @retval true if the signature is valid
   * @retval false if the signature is invalid
   */
  static bool Verify(
      const SchnorrSignature &signature, const ByteData256 &msg,
      const Pubkey &pubkey);
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_SCHNORRSIG_H_
