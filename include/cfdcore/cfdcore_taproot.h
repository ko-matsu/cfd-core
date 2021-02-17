// Copyright 2021 CryptoGarage
/**
 * @file cfdcore_taproot.h
 *
 * @brief This file defines the taproot utility class.
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TAPROOT_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TAPROOT_H_

#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_util.h"

namespace cfd {
namespace core {

/**
 * @brief This class implements a taproot merkle tree.
 * @see https://bitcoinops.org/en/newsletters/2019/05/14/
 */
class CFD_CORE_EXPORT TaprootMerkleTree {
 public:
  /**
   * @brief The taproot control node maximum count.
   */
  static constexpr size_t kTaprootControlMaxNodeCount = 128;
  /**
   * @brief The tapleaf version on tapscript.
   */
  static constexpr uint8_t kTapScriptLeafVersion = 0xc0;

  /**
   * @brief constructor.
   */
  TaprootMerkleTree();
  /**
   * @brief constructor.
   * @param[in] script  tapscript
   */
  explicit TaprootMerkleTree(const Script& script);
  /**
   * @brief constructor.
   * @param[in] leaf_version    leaf version
   * @param[in] script          tapscript
   */
  explicit TaprootMerkleTree(uint8_t leaf_version, const Script& script);
  /**
   * @brief copy constructor.
   * @param[in] tap_tree    tree object
   */
  TaprootMerkleTree(const TaprootMerkleTree& tap_tree);
  /**
   * @brief destructor.
   */
  virtual ~TaprootMerkleTree() {}

  /**
   * @brief Add branch.
   * @param[in] pubkey  schnorr pubkey
   */
  void AddBranch(const SchnorrPubkey& pubkey);
  /**
   * @brief Add branch.
   * @param[in] node    tweak or other branch or tapleaf hash.
   */
  void AddBranch(const ByteData256& node);

  /**
   * @brief Get a tapleaf hash.
   * @return tapleaf hash.
   */
  ByteData256 GetTapLeafHash() const;
  /**
   * @brief Get a current branch hash.
   * @return branch hash.
   */
  ByteData256 GetCurrentBranchHash() const;
  /**
   * @brief Get tweak.
   * @param[in] internal_pubkey     internal pubkey
   * @return tweak.
   */
  ByteData256 GetTweak(const SchnorrPubkey& internal_pubkey) const;

  /**
   * @brief Get a tweaked pubkey.
   * @param[in] internal_pubkey     internal pubkey
   * @param[out] parity             parity flag.
   * @return tweaked schnorr pubkey.
   */
  SchnorrPubkey GetTweakedPubkey(
      const SchnorrPubkey& internal_pubkey, bool* parity = nullptr) const;

  /**
   * @brief Get a tweaked privkey.
   * @param[in] internal_privkey    internal privkey
   * @param[out] parity             parity flag.
   * @return tweaked privkey.
   */
  Privkey GetTweakedPrivkey(
      const Privkey& internal_privkey, bool* parity = nullptr) const;

  /**
   * @brief Get a leaf version.
   * @return leaf version.
   */
  uint8_t GetLeafVersion() const;

  /**
   * @brief Get a tapscript.
   * @return tapscript.
   */
  Script GetScript() const;

  /**
   * @brief Get a node list.
   * @return node list.
   */
  std::vector<ByteData256> GetNodeList() const;

 private:
  uint8_t leaf_version_;            //!< leaf version
  Script script_;                   //!< tapscript
  std::vector<ByteData256> nodes_;  //!< node list
};

/**
 * @brief This class contain utility functions to work with taproot.
 */
class CFD_CORE_EXPORT TaprootUtil {
 public:
  /**
   * @brief Check valid leaf version.
   * @param[in] leaf_version    leaf version
   * @retval true   valid
   * @retval false  invalid
   */
  static bool IsValidLeafVersion(uint8_t leaf_version);

  /**
   * @brief create tapscript control data.
   * @param[in] internal_pubkey     internal pubkey
   * @param[in] merkle_tree         merkle tree
   * @param[out] witness_program    witness program
   * @param[out] locking_script     taproot locking script
   * @return tapscript control data.
   */
  static ByteData CreateTapScriptControl(
      const SchnorrPubkey& internal_pubkey,
      const TaprootMerkleTree& merkle_tree,
      SchnorrPubkey* witness_program = nullptr,
      Script* locking_script = nullptr);

  /**
   * @brief Verify taproot commitment.
   * @param[in] has_parity          parity flag
   * @param[in] tapleaf_bit         tapleaf bit
   * @param[in] target_taproot      witness program
   * @param[in] internal_pubkey     internal pubkey
   * @param[in] nodes               taptree node list
   * @param[in] tapscript           tapscript
   * @param[out] tapleaf_hash       tapleaf hash
   * @retval true   valid
   * @retval false  invalid
   */
  static bool VerifyTaprootCommitment(
      bool has_parity, uint8_t tapleaf_bit,
      const SchnorrPubkey& target_taproot,
      const SchnorrPubkey& internal_pubkey,
      const std::vector<ByteData256>& nodes, const Script& tapscript,
      ByteData256* tapleaf_hash = nullptr);

  /**
   * @brief Parse taproot sign (witness stack) data
   * @param[in] witness_stack       witness stack
   * @param[out] schnorr_signature  schnorr signature
   * @param[out] has_parity         parity flag
   * @param[out] tapleaf_bit        tapleaf bit
   * @param[out] internal_pubkey    internal pubkey
   * @param[out] nodes              taproot node list
   * @param[out] tapscript          tapscript
   * @param[out] stack              script stack data
   * @param[out] annex              annex data
   */
  static void ParseTaprootSignData(
      const std::vector<ByteData>& witness_stack,
      SchnorrSignature* schnorr_signature, bool* has_parity,
      uint8_t* tapleaf_bit, SchnorrPubkey* internal_pubkey,
      std::vector<ByteData256>* nodes, Script* tapscript,
      std::vector<ByteData>* stack = nullptr, ByteData* annex = nullptr);
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TAPROOT_H_
