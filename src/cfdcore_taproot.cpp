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
// TapBranch
// ----------------------------------------------------------------------------
TapBranch::TapBranch() : has_leaf_(false), leaf_version_(0) {}

TapBranch::TapBranch(const ByteData256& commitment)
    : has_leaf_(false), leaf_version_(0) {
  root_commitment_ = commitment;
}

TapBranch::TapBranch(const TapBranch& tap_tree) {
  has_leaf_ = tap_tree.has_leaf_;
  leaf_version_ = tap_tree.leaf_version_;
  script_ = tap_tree.script_;
  root_commitment_ = tap_tree.root_commitment_;
  branch_list_ = tap_tree.branch_list_;
}

void TapBranch::AddBranch(const SchnorrPubkey& pubkey) {
  AddBranch(pubkey.GetByteData256());
}

void TapBranch::AddBranch(const ByteData256& commitment) {
  branch_list_.emplace_back(commitment);
}

void TapBranch::AddBranch(const TapBranch& branch) {
  branch_list_.emplace_back(branch);
}

TapBranch& TapBranch::operator=(const TapBranch& object) {
  if (this != &object) {
    has_leaf_ = object.has_leaf_;
    leaf_version_ = object.leaf_version_;
    script_ = object.script_;
    root_commitment_ = object.root_commitment_;
    branch_list_ = object.branch_list_;
  }
  return *this;
}

ByteData256 TapBranch::GetRootHash() const {
  if (!has_leaf_) return root_commitment_;

  auto tagged_hash = HashUtil::Sha256("TapLeaf");
  //auto& hasher = HashUtil(HashUtil::kSha256)
  auto& builder = Serializer()
                 << tagged_hash << tagged_hash
                 << leaf_version_
                 << script_.GetData().Serialize();
  //             << ByteData(&leaf_version_, 1)
  // return hasher.Output256();
  return HashUtil::Sha256(builder.Output());
}

ByteData256 TapBranch::GetCurrentBranchHash() const {
  ByteData256 hash = GetRootHash();
  if (branch_list_.empty()) return hash;

  auto tagged_hash = HashUtil::Sha256("TapBranch");
  ByteData tapbranch_base = tagged_hash.Concat(tagged_hash);
  auto nodes = GetNodeList();
  for (const auto& node : nodes) {
    auto& hasher = HashUtil(HashUtil::kSha256) << tapbranch_base;
    const auto& node_bytes = node.GetBytes();
    const auto& hash_bytes = hash.GetBytes();
    if (std::lexicographical_compare(
            hash_bytes.begin(), hash_bytes.end(), node_bytes.begin(),
            node_bytes.end())) {
      hash = (hasher << hash << node).Output256();
    } else {
      hash = (hasher << node << hash).Output256();
    }
  }
  return hash;
}

bool TapBranch::HasTapLeaf() const { return has_leaf_; }

uint8_t TapBranch::GetLeafVersion() const { return leaf_version_; }

Script TapBranch::GetScript() const { return script_; }

std::vector<TapBranch> TapBranch::GetBranchList() const {
  return branch_list_;
}

std::vector<ByteData256> TapBranch::GetNodeList() const {
  std::vector<ByteData256> list;
  for (const auto& branch : branch_list_) {
    list.emplace_back(branch.GetCurrentBranchHash());
  }
  return list;
}

std::string TapBranch::ToString() const {
  std::string buf;
  if (has_leaf_) {
    buf = "tapleaf(" + std::to_string(leaf_version_) + ",tapscript(" +
          script_.GetHex() + "))";
  } else {
    buf = root_commitment_.GetHex();
  }
  if (branch_list_.empty()) return buf;

  ByteData256 hash = GetRootHash();
  auto tagged_hash = HashUtil::Sha256("TapBranch");
  ByteData tapbranch_base = tagged_hash.Concat(tagged_hash);
  auto nodes = GetNodeList();
  for (const auto& branch : branch_list_) {
    auto& hasher = HashUtil(HashUtil::kSha256) << tapbranch_base;
    const auto node = branch.GetCurrentBranchHash();
    const auto& node_bytes = node.GetBytes();
    const auto& hash_bytes = hash.GetBytes();
    if (std::lexicographical_compare(
            hash_bytes.begin(), hash_bytes.end(), node_bytes.begin(),
            node_bytes.end())) {
      hash = (hasher << hash << node).Output256();
      buf = "tap_br(" + buf + "," + branch.ToString() + ")";
    } else {
      hash = (hasher << node << hash).Output256();
      buf = "tap_br(" + branch.ToString() + "," + buf + ")";
    }
  }
  return buf;
}

#if 0  // for feature
TapBranch TapBranch::FromString(const std::string& text) {
  // tap_br(tap_br(A,B),tap_br(tap_br(C),tapleaf(192,1122330011221100)))
  for (size_t idx = 0; idx < text.size(); ++idx) {
    const char& str = text[idx];
  }
  return TapBranch();
}
#endif

// ----------------------------------------------------------------------------
// TaprootScriptTree
// ----------------------------------------------------------------------------
TaprootScriptTree::TaprootScriptTree() : TapBranch() {
  has_leaf_ = true;
  leaf_version_ = kTapScriptLeafVersion;
}

TaprootScriptTree::TaprootScriptTree(const Script& script)
    : TaprootScriptTree(kTapScriptLeafVersion, script) {}

TaprootScriptTree::TaprootScriptTree(
    uint8_t leaf_version, const Script& script)
    : TapBranch() {
  has_leaf_ = true;
  leaf_version_ = leaf_version;
  script_ = script;
  if (!TaprootUtil::IsValidLeafVersion(leaf_version)) {
    warn(CFD_LOG_SOURCE, "Unsupported leaf version. [{}]", leaf_version);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Unsupported leaf version.");
  }
}

TaprootScriptTree::TaprootScriptTree(const TapBranch& leaf_branch)
    : TapBranch(leaf_branch) {
  if (!leaf_branch.HasTapLeaf()) {
    warn(CFD_LOG_SOURCE, "object is not tapleaf.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "object is not tapleaf.");
  }
  if (!TaprootUtil::IsValidLeafVersion(leaf_branch.GetLeafVersion())) {
    warn(
        CFD_LOG_SOURCE, "Unsupported leaf version. [{}]",
        leaf_branch.GetLeafVersion());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Unsupported leaf version.");
  }
  has_leaf_ = true;
  leaf_version_ = leaf_branch.GetLeafVersion();
  script_ = leaf_branch.GetScript();
  branch_list_ = leaf_branch.GetBranchList();
  nodes_ = leaf_branch.GetNodeList();
}

TaprootScriptTree::TaprootScriptTree(const TaprootScriptTree& tap_tree)
    : TapBranch(tap_tree) {
  if (!TaprootUtil::IsValidLeafVersion(tap_tree.leaf_version_)) {
    warn(
        CFD_LOG_SOURCE, "Unsupported leaf version. [{}]",
        tap_tree.leaf_version_);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Unsupported leaf version.");
  }
  has_leaf_ = tap_tree.has_leaf_;
  leaf_version_ = tap_tree.leaf_version_;
  script_ = tap_tree.script_;
  root_commitment_ = tap_tree.root_commitment_;
  branch_list_ = tap_tree.branch_list_;
  nodes_ = tap_tree.nodes_;
}

TaprootScriptTree& TaprootScriptTree::operator=(
    const TaprootScriptTree& object) & {
  if (this != &object) {
    has_leaf_ = object.has_leaf_;
    leaf_version_ = object.leaf_version_;
    script_ = object.script_;
    root_commitment_ = object.root_commitment_;
    branch_list_ = object.branch_list_;
    nodes_ = object.nodes_;
  }
  return *this;
}

void TaprootScriptTree::AddBranch(const ByteData256& commitment) {
  TapBranch::AddBranch(commitment);
  nodes_.emplace_back(commitment);
}

void TaprootScriptTree::AddBranch(const TapBranch& branch) {
  TapBranch::AddBranch(branch);
  nodes_.emplace_back(branch.GetCurrentBranchHash());
}

void TaprootScriptTree::AddBranch(const TaprootScriptTree& tree) {
  TapBranch::AddBranch(tree);
  nodes_.emplace_back(tree.GetCurrentBranchHash());
}

ByteData256 TaprootScriptTree::GetTapLeafHash() const { return GetRootHash(); }

ByteData256 TaprootScriptTree::GetTapTweak(
    const SchnorrPubkey& internal_pubkey) const {
  ByteData256 hash = GetCurrentBranchHash();
  auto tagged_hash = HashUtil::Sha256("TapTweak");
  auto& hasher = HashUtil(HashUtil::kSha256)
                 << tagged_hash << tagged_hash << internal_pubkey.GetData()
                 << hash;
  return hasher.Output256();
}

SchnorrPubkey TaprootScriptTree::GetTweakedPubkey(
    const SchnorrPubkey& internal_pubkey, bool* parity) const {
  ByteData256 hash = GetTapTweak(internal_pubkey);
  return internal_pubkey.CreateTweakAdd(hash, parity);
}

Privkey TaprootScriptTree::GetTweakedPrivkey(
    const Privkey& internal_privkey, bool* parity) const {
  bool is_parity = false;
  auto internal_pubkey =
      SchnorrPubkey::FromPrivkey(internal_privkey, &is_parity);
  Privkey privkey = internal_privkey;
  if (is_parity) privkey = internal_privkey.CreateNegate();

  ByteData256 hash = GetTapTweak(internal_pubkey);
  internal_pubkey.CreateTweakAdd(hash, &is_parity);
  if (parity != nullptr) *parity = is_parity;
  return privkey.CreateTweakAdd(hash);
}

std::vector<ByteData256> TaprootScriptTree::GetNodeList() const {
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
    const SchnorrPubkey& internal_pubkey, const TaprootScriptTree& merkle_tree,
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
  if (nodes.size() > TaprootScriptTree::kTaprootControlMaxNodeCount) {
    warn(CFD_LOG_SOURCE, "control node maximum over. [{}]", nodes.size());
    return false;
  }

  // Compute the tapleaf hash.
  TaprootScriptTree tree(tapleaf_bit, tapscript);
  if (tapleaf_hash != nullptr) *tapleaf_hash = tree.GetTapLeafHash();

  // Compute the Merkle root from the leaf and the provided path.
  for (const auto& node : nodes) {
    tree.AddBranch(node);
  }
  // Compute the tweak from the Merkle root and the inner pubkey.
  auto hash = tree.GetTapTweak(internal_pubkey);
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

  size_t size = witness_stack.size();
  if ((size >= 2) && (!witness_stack.back().IsEmpty()) &&
      (witness_stack.back().GetHeadData() == kAnnexTag)) {
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
    if (max_node > TaprootScriptTree::kTaprootControlMaxNodeCount) {
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
