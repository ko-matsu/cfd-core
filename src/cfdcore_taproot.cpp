// Copyright 2021 CryptoGarage
/**
 * @file cfdcore_taproot.cpp
 *
 * @brief This file implements for taproot utility class.
 */

#include "cfdcore/cfdcore_taproot.h"

#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_transaction_common.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

using logger::warn;

// ----------------------------------------------------------------------------
// TaprootMerkleTree
// ----------------------------------------------------------------------------
TaprootMerkleTree::TaprootMerkleTree()
    : leaf_version_(kTapScriptLeafVersion) {}

TaprootMerkleTree::TaprootMerkleTree(const Script& script)
    : TaprootMerkleTree(kTapScriptLeafVersion, script) {}

TaprootMerkleTree::TaprootMerkleTree(
    uint8_t leaf_version, const Script& script)
    : leaf_version_(leaf_version), script_(script) {
  if (!TaprootUtil::IsValidLeafVersion(leaf_version)) {
    warn(CFD_LOG_SOURCE, "Unsupported leaf version. [{}]", leaf_version);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Unsupported leaf version.");
  }
}

TaprootMerkleTree::TaprootMerkleTree(const TaprootMerkleTree& tap_tree) {
  leaf_version_ = tap_tree.leaf_version_;
  script_ = tap_tree.script_;
  nodes_ = tap_tree.nodes_;
}

void TaprootMerkleTree::AddBranch(const SchnorrPubkey& pubkey) {
  nodes_.emplace_back(pubkey.GetByteData256());
}

void TaprootMerkleTree::AddBranch(const ByteData256& tweak) {
  nodes_.emplace_back(tweak);
}

ByteData256 TaprootMerkleTree::GetTapLeafHash() const {
  Serializer builder;
  auto tagged_hash = HashUtil::Sha256("TapLeaf");
  builder.AddDirectBytes(tagged_hash);
  builder.AddDirectBytes(tagged_hash);
  builder.AddDirectByte(leaf_version_);
  builder.AddDirectBytes(script_.GetData().Serialize());
  return HashUtil::Sha256(builder.Output());
}

ByteData256 TaprootMerkleTree::GetCurrentBranchHash() const {
  ByteData256 hash = GetTapLeafHash();

  auto tagged_hash = HashUtil::Sha256("TapBranch");
  ByteData tapbranch_base = tagged_hash.Concat(tagged_hash);
  for (const auto& node : nodes_) {
    const auto& node_bytes = node.GetBytes();
    const auto& hash_bytes = hash.GetBytes();
    if (std::lexicographical_compare(
            hash_bytes.begin(), hash_bytes.end(), node_bytes.begin(),
            node_bytes.end())) {
      hash = HashUtil::Sha256(tapbranch_base.Concat(hash, node));
    } else {
      hash = HashUtil::Sha256(tapbranch_base.Concat(node, hash));
    }
  }
  return hash;
}

ByteData256 TaprootMerkleTree::GetTweak(
    const SchnorrPubkey& internal_pubkey) const {
  ByteData256 hash = GetCurrentBranchHash();
  auto tagged_hash = HashUtil::Sha256("TapTweak");
  return HashUtil::Sha256(
      tagged_hash.Concat(tagged_hash, internal_pubkey.GetData(), hash));
}

SchnorrPubkey TaprootMerkleTree::GetTweakedPubkey(
    const SchnorrPubkey& internal_pubkey, bool* parity) const {
  ByteData256 hash = GetTweak(internal_pubkey);
  return internal_pubkey.CreateTweakAdd(hash, parity);
}

Privkey TaprootMerkleTree::GetTweakedPrivkey(
    const Privkey& internal_privkey, bool* parity) const {
  bool is_parity = false;
  auto internal_pubkey =
      SchnorrPubkey::FromPrivkey(internal_privkey, &is_parity);
  Privkey privkey = internal_privkey;
  if (is_parity) privkey = internal_privkey.CreateNegate();

  ByteData256 hash = GetTweak(internal_pubkey);
  internal_pubkey.CreateTweakAdd(hash, &is_parity);
  if (parity != nullptr) *parity = is_parity;
  return privkey.CreateTweakAdd(hash);
}

uint8_t TaprootMerkleTree::GetLeafVersion() const { return leaf_version_; }

Script TaprootMerkleTree::GetScript() const { return script_; }

std::vector<ByteData256> TaprootMerkleTree::GetNodeList() const {
  return nodes_;
}

// ----------------------------------------------------------------------------
// TaprootUtil
// ----------------------------------------------------------------------------
bool TaprootUtil::IsValidLeafVersion(uint8_t leaf_version) {
  // BIP-0341
  static const uint32_t kValidLeafVersions[] = {0x66, 0x7e, 0x80, 0x84, 0x96,
                                                0x98, 0xba, 0xbc, 0xbe};
  for (auto valid_ver : kValidLeafVersions) {
    if (leaf_version == valid_ver) return true;
  }

  if ((leaf_version % 2) != 0) return false;  // Odd
  if ((leaf_version >= 0xc0) && (leaf_version <= 0xfe)) return true;
  return false;
}

ByteData TaprootUtil::CreateTapScriptControl(
    const SchnorrPubkey& internal_pubkey, const TaprootMerkleTree& merkle_tree,
    SchnorrPubkey* witness_program, Script* locking_script) {
  bool parity = false;
  auto pubkey_data =
      merkle_tree.GetTweakedPubkey(internal_pubkey, &parity).GetByteData256();
  uint8_t top = merkle_tree.GetLeafVersion();
  if (parity) top |= 0x01;
  Serializer builder;
  builder.AddDirectByte(top);
  builder.AddDirectBytes(internal_pubkey.GetData());
  for (const auto& node : merkle_tree.GetNodeList()) {
    builder.AddDirectBytes(node);
  }
  if (witness_program != nullptr) {
    *witness_program = SchnorrPubkey(pubkey_data);
  }
  if (locking_script != nullptr) {
    *locking_script = ScriptUtil::CreateTaprootLockingScript(pubkey_data);
  }
  return builder.Output();
}

bool TaprootUtil::VerifyTaprootCommitment(
    bool has_parity, uint8_t tapleaf_bit,
    const SchnorrPubkey& target_taproot,  // witness program
    const SchnorrPubkey& internal_pubkey,
    const std::vector<ByteData256>& nodes, const Script& tapscript,
    ByteData256* tapleaf_hash) {
  if (nodes.size() > TaprootMerkleTree::kTaprootControlMaxNodeCount) {
    warn(CFD_LOG_SOURCE, "control node maximum over. [{}]", nodes.size());
    return false;
  }

  // Compute the tapleaf hash.
  TaprootMerkleTree tree(tapleaf_bit, tapscript);
  if (tapleaf_hash != nullptr) *tapleaf_hash = tree.GetTapLeafHash();

  // Compute the Merkle root from the leaf and the provided path.
  for (const auto& node : nodes) {
    tree.AddBranch(node);
  }
  // Compute the tweak from the Merkle root and the inner pubkey.
  auto hash = tree.GetTweak(internal_pubkey);
  // Verify that the output pubkey matches the tweaked inner pubkey, after correcting for parity. // NOLINT
  return target_taproot.IsTweaked(internal_pubkey, hash, has_parity);
}

void TaprootUtil::ParseTaprootSignData(
    const std::vector<ByteData>& witness_stack,
    SchnorrSignature* schnorr_signature, bool* has_parity,
    uint8_t* tapleaf_bit, SchnorrPubkey* internal_pubkey,
    std::vector<ByteData256>* nodes, Script* tapscript,
    std::vector<ByteData>* stack, ByteData* annex) {
  static constexpr uint8_t kAnnexTag = 0x50;
  static constexpr size_t kControlMinimumSize =
      SchnorrPubkey::kSchnorrPubkeySize + 1;

  bool exist_annex = false;
  size_t size = witness_stack.size();
  if ((size >= 2) && (!witness_stack.back().IsEmpty()) &&
      (witness_stack.back().GetHeadData() == kAnnexTag)) {
    exist_annex = true;
    if (annex != nullptr) *annex = witness_stack.back();
    --size;
  }

  if (size == 0) {
    warn(CFD_LOG_SOURCE, "witness_stack is empty.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "witness_stack is empty.");
  } else if (size == 1) {
    if (schnorr_signature != nullptr) {
      *schnorr_signature = SchnorrSignature(witness_stack.at(0));
    }
  } else {
    Script script(witness_stack.at(size - 2));
    ByteData data = witness_stack.at(size - 1);
    if ((data.GetDataSize() < kControlMinimumSize) ||
        (((data.GetDataSize() - 1) % kByteData256Length) != 0)) {
      warn(CFD_LOG_SOURCE, "wrong taproot control size.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "wrong taproot control size.");
    }
    size_t max_node =
        (data.GetDataSize() - kControlMinimumSize) / kByteData256Length;
    if (max_node > TaprootMerkleTree::kTaprootControlMaxNodeCount) {
      warn(
          CFD_LOG_SOURCE, "taproot control node maximum over. [{}]", max_node);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "taproot control node maximum over.");
    }

    Deserializer parser(data);
    uint8_t top = parser.ReadUint8();
    if (has_parity != nullptr) *has_parity = (top & 0x01);
    if (tapleaf_bit != nullptr) *tapleaf_bit = top & 0xfe;

    ByteData256 pubkey_bytes(parser.ReadBuffer(kByteData256Length));
    if (internal_pubkey != nullptr) {
      *internal_pubkey = SchnorrPubkey(pubkey_bytes);
    }
    if (nodes != nullptr) {
      for (size_t index = 0; index < max_node; ++index) {
        ByteData256 node(parser.ReadBuffer(kByteData256Length));
        nodes->emplace_back(node);
      }
    }

    if (tapscript != nullptr) *tapscript = script;
    if ((stack != nullptr) && (size > 2)) {
      for (size_t index = 0; index < size - 2; ++index) {
        stack->emplace_back(witness_stack.at(index));
      }
    }
  }
}

}  // namespace core
}  // namespace cfd
