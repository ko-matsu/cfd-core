// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_script.cpp
 *
 * @brief Script関連クラス実装
 *
 */

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_descriptor.h"

namespace cfd {
namespace core {

using logger::warn;

struct DescriptorNodeScriptData {
  std::string name;
  DescriptorScriptType type;
  bool top_only;
  bool has_child;
  bool multisig;
};

static const DescriptorNodeScriptData kDescriptorNodeScriptTable[] = {
  {"sh", DescriptorScriptType::kDescriptorScriptSh, true, true, false},
  {"combo", DescriptorScriptType::kDescriptorScriptCombo, true, true, false},
  {"wsh", DescriptorScriptType::kDescriptorScriptWsh, false, true, false},
  {"pk", DescriptorScriptType::kDescriptorScriptPk, false, true, false},
  {"pkh", DescriptorScriptType::kDescriptorScriptPkh, false, true, false},
  {"wpkh", DescriptorScriptType::kDescriptorScriptWpkh, false, true, false},
  {"multi", DescriptorScriptType::kDescriptorScriptMulti, false, true, true},
  {"sortedmulti", DescriptorScriptType::kDescriptorScriptSortedMulti, false, true, true},
  {"addr", DescriptorScriptType::kDescriptorScriptAddr, true, true, false},
  {"raw", DescriptorScriptType::kDescriptorScriptRaw, true, true, false},
};


// -----------------------------------------------------------------------------
// DescriptorNode
// -----------------------------------------------------------------------------
DescriptorNode::DescriptorNode() {
}

DescriptorNode DescriptorNode::Parse(const std::string& output_descriptor) {
  DescriptorNode node;
  node.AnalyzeChild(output_descriptor, 0);
  if (output_descriptor.child_node_.size() != 1) {
    warn(CFD_LOG_SOURCE, "Illegal child node num.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Illegal child node num.");
  }
  output_descriptor.child_node_[0].AnalyzeAll("");
  return output_descriptor.child_node_[0];
}

void DescriptorNode::AnalyzeChild(const std::string& descriptor, uint32_t depth) {
  bool is_terminate = false;
  size_t offset = 0;
  uint32_t depth_work = depth;
  bool checksum = false;
  depth_ = depth;

  for (size_t idx=0; idx<descriptor.size(); ++idx) {
    const char& str = descriptor[idx];
    if (is_terminate) {
      if (descriptor[idx] == '#') {
        checksum = true;
        offset = idx;
        checksum_ = descriptor.substr(idx + 1);
      } else if (!checksum) {
        warn(CFD_LOG_SOURCE, "Illegal checksum data.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError, "Illegal checksum data.");
      }
    }
    else if (descriptor[idx] == ',') {
      if (exist_child_node) {
        warn(CFD_LOG_SOURCE, "Failed exist child node after terminate.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError, "Failed exist child node after terminate.");
      } else if ((name_ == "multi") || (name_ == "sortedmulti")) {
        DescriptorNode node;
        node.value_ = descriptor.substr(offset, idx);
        if (child_node_.empty()) {
          node.node_type_ = DescriptorNodeType::kDescriptorTypeNumber;
          node.number_ = atoi(node.value_.c_str());
        } else {
          node.node_type_ = DescriptorNodeType::kDescriptorTypeKey;
        }
        node.depth_ = depth + 1;
        child_node_.push_back(node);
      } else {
        warn(CFD_LOG_SOURCE, "Illegal command.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError, "Illegal command.");
      }
      offset = idx + 1;
    }
    else if (str == ' ') {
      ++offset;
    }
    else if (str == '(') {
      if (depth_work == depth) {
        name_ = descriptor.substr(offset, idx);
        offset = idx + 1;
      } else {
        exist_child_node = true;
      }
      ++depth_work;
    }
    else if (str == ')') {
      --depth_work;
      if (depth_work == depth) {
        value_ = descriptor.substr(offset, idx - offset);
        is_terminate = true;
        offset = idx + 1;
        if ((name_ == "addr") || (name_ == "raw")) {
          // do nothing
        } else {
          DescriptorNode node;
          if (exist_child_node) {
            node.AnalyzeChild(value_, depth + 1);
            exist_child_node = false;
          } else {
            node.node_type_ = DescriptorNodeType::kDescriptorTypeKey;
            node.value_ = value_;
            node.depth_ = depth + 1;
          }
          child_node_.push_back(node);
        }
      }
    }
  }

  if (name_.empty() || (name_ == "addr") || (name_ == "raw")) {
    // do nothing
  }
  else if (child_node_.empty()) {
    warn(CFD_LOG_SOURCE, "Failed child node empty.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed child node empty.");
  }

}

void DescriptorNode::AnalyzeAll(const std::string& parent_name) {
  if (name_.empty()) {
    // key analyze
    key_info_ = value_;
    if (value_[0] == '[') {
      // key origin information check
      // cut to ']'
      int pos = value_.find("]");
      if (pos != std::string::npos) {
        key_info_ = value_.substr(pos + 1);
      }
    }
    // derive key check (xpub,etc)
    std::string hdkey_top = key_info_.substr(0, 4);
    if ((hdkey_top == "xpub") || (hdkey_top == "tpub") || (hdkey_top == "xprv") || (hdkey_top == "tprv")) {
      key_type_ = DescriptorKeyType::kDescriptorKeyBip32;
      if ((hdkey_top == "xprv") || (hdkey_top == "tprv")) {
        key_type_ = kDescriptorKeyBip32PrivkDescriptorKeyBip32Priv;
      }
      if (key_info_.find("*") != std::string::npos) {
        need_arg_num_ = 1;
      }
      // FIXME 
      key_info_ = key_info_;  // Keyクラスをserializeする
    }
    else {
      key_type_ = DescriptorKeyType::kDescriptorKeyPublic;
      bool is_wif = false;
      Pubkey pubkey;
      try {
        // pubkey format check
        ByteData bytes(key_info_);
        if (Pubkey::IsValid(bytes)) {
          // pubkey
          pubkey = Pubkey(bytes);
        } else {
          // privkey
          privkey = Privkey(bytes);
          pubkey = privkey.GeneratePubkey();
        }
      } catch (const CfdException& except) {
        std::string errmsg(except.what());
        if (errmsg.find("hex to byte convert error.") != std::string::npos) {
          is_wif = true;
        }
      }
      if (is_wif) {
        // privkey WIF check
        try {
          privkey = Privkey::FromWif(key_info_, NetType::kMainnet);
        } catch (const CfdException& except) {
          std::string errmsg(except.what());
          if (errmsg.find("Error WIF to Private key.") != std::string::npos) {
            privkey = Privkey::FromWif(key_info_, NetType::kTestnet);
          }
        }
        if (privkey.IsInvalid()) {
          // throw
        }
        pubkey = privkey.GeneratePubkey();
        key_info_ = pubkey.GetHex();
      }
    }
    return;
  }

  const DescriptorNodeScriptData* p_data = nullptr;
  for (const auto& node_data : kDescriptorNodeScriptTable) {
    if (name_ == node_data.name) {
      p_data = &node_data;
    }
  }
  if (p_data == nullptr) {
    warn(CFD_LOG_SOURCE, "Failed unknown name.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed unknown name.");
  }

  if (p_data->top_only && (depth_ != 0)) {
    warn(CFD_LOG_SOURCE, "Failed depth is not zero.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed depth is not zero.");
  }
  if (p_data->has_child) {
    if (child_node_.empty()) {
      warn(CFD_LOG_SOURCE, "Failed child node empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Failed child node empty.");
    }
  } else if (!child_node_.empty()) {
    warn(CFD_LOG_SOURCE, "Failed child node num. size={}", child_node_.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed child node num.");
  }

  if (p_data->multisig) {
    if (child_node_.size() < 2) {
      warn(CFD_LOG_SOURCE, "Failed multisig node low. size={}", child_node_.size());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Failed multisig node low.");
    }
    if (child_node_[0].number_ == 0) {
      warn(CFD_LOG_SOURCE, "Failed multisig require num. num={}", child_node_[0].number_);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Failed multisig require num.");
    }
    for (auto& child : child_node_) {
      child.AnalyzeAll(name_);
    }
  }
  else if (name_ == "addr") {
    // check address format
    // プレフィックス判定どうする？
    // FIXME network種別を指定して貰う必要がある。btcならともかくelmentsは。
  }
  else if (name_ == "raw")) {
    ByteData bytes(value_);
    bytes.GetHex();
  }
  else if (child_node_.size() != 1) {
    warn(CFD_LOG_SOURCE, "Failed child node num. size={}", child_node_.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed child node num.");
  }
  else {
    if ((name_ == "wsh") && (!parent_name.empty()) && (parent_name != "sh")) {
      warn(CFD_LOG_SOURCE, "Failed wsh parent. only top or sh.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Failed wsh parent. only top or sh.");
    }
    else if ((name_ == "wpkh") && (parent_name == "wsh")) {
      warn(CFD_LOG_SOURCE, "Failed wpkh parent. cannot wsh.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Failed wpkh parent. cannot wsh.");
      // parent_name、リスト指定にしたほうがいいかも。
    }
    child_node_[0].AnalyzeAll(name_);
  }
  script_type_ = p_data->type;
}

Script DescriptorNode::GenerateScript(std::vector<std::string>* array_argument) const {
  ScriptBuilder build;
  Script locking_script;
  if (node_type_ == DescriptorNodeType::kDescriptorTypeKey) {
    Pubkey pubkey = GetPubkey(array_argument);
    build.AppendData(pubkey);
  }
  else if (node_type_ == DescriptorNodeType::kDescriptorTypeScript) {
    if (script_type_ == DescriptorScriptType::kDescriptorScriptRaw) {
      return Script(value_);
    }
    else if (script_type_ == DescriptorScriptType::kDescriptorScriptAddr) {
      // FIXME network種別を指定して貰う必要がある。btcならともかくelmentsは。
      Address addr(value_);
      return addr.GetLockingScript();
    }
    if ((script_type_ == DescriptorScriptType::kDescriptorScriptMulti) ||
        (script_type_ == DescriptorScriptType::kDescriptorScriptSortedMulti)) {
      uint32_t reqnum = child_node_[0].number_;
      std::vector<Pubkey> pubkeys;
      if (script_type_ == DescriptorScriptType::kDescriptorScriptSortedMulti) {
        // https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki
        // FIXME sort -> Pubkey用のcompare関数(lambda)を作ってソートする。
      }
      for (size_t index = 1; index < child_node_.size(); ++index) {
        pubkeys.push_back(child_node_[index].GetPubkey(array_argument));
      }
      return ScriptUtil::CreateMultisigRedeemScript(reqnum, pubkeys);
    }
    else if ((script_type_ == DescriptorScriptType::kDescriptorScriptSh) ||
        (script_type_ == DescriptorScriptType::kDescriptorScriptWsh)) {
      Script redeem_script = child_node_[0].GenerateScript(
          array_argument);
      if (script_type_ == DescriptorScriptType::kDescriptorScriptWsh) {
        locking_script = ScriptUtil::CreateP2wshLockingScript(redeem_script);
      } else {
        locking_script = ScriptUtil::CreateP2shLockingScript(redeem_script);
      }
      return locking_script;
    }

    Pubkey pubkey = child_node_[0].GetPubkey(array_argument);
    if (script_type_ == DescriptorScriptType::kDescriptorScriptPk) {
      build.AppendData(pubkey);
      build.AppendOperator(ScriptOperator::OP_CHECKSIG);
    }
    else {
      if (script_type_ == DescriptorScriptType::kDescriptorScriptCombo) {
        if (pubkey.IsCompress()) {
          // p2wpkh
          locking_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
        } else {
          // p2pkh
          locking_script = ScriptUtil::CreateP2pkhLockingScript(pubkey);
        }
      }
      else if (script_type_ == DescriptorScriptType::kDescriptorScriptPkh) {
        locking_script = ScriptUtil::CreateP2pkhLockingScript(pubkey);
      }
      else if (script_type_ == DescriptorScriptType::kDescriptorScriptWpkh) {
        locking_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
      }
      return locking_script;
    }
  }
  else if (node_type_ == DescriptorNodeType::kDescriptorTypeNumber) {.
    ScriptElement elem(static_cast<int64_t>(number_));
    build.AppendElement(elem);
  }
  else {
    // do nothing
  }
  return build.Build();
}

Pubkey DescriptorNode::GetPubkey(std::vector<std::string>* array_argument) {
  Pubkey pubkey;
  if (child_node_[0].key_type_ == DescriptorKeyType::kDescriptorKeyPublic) {
    pubkey = Pubkey(child_node_[0].key_info_);
  }
  else if (need_arg_num_ == 0) {
    // FIXME HDkey
    // 指定キー
    // 強化鍵の場合、xprv/tprvの必要あり
  }
  else {
    // FIXME HDkey
    // 動的キー生成。文字列からパス一覧を生成する必要あり。
    // 強化鍵の場合、xprv/tprvの必要あり
  }

  if (!pubkey.IsValid()) {
    warn(CFD_LOG_SOURCE, "Failed pubkey.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed pubkey data.");
  }
  return pubkey;
}


std::vector<Script> DescriptorNode::GetComboScript(std::vector<std::string>* array_argument) const {
  if (script_type_ != DescriptorScriptType::kDescriptorScriptCombo) {
    warn(CFD_LOG_SOURCE, "Illegal node. only `combo`.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Illegal node. only `combo`.");
  }
  std::vector<Script> result;
  Pubkey pubkey = GetChildPubkey(array_argument);

  if (pubkey.IsCompress()) {
    // p2wpkh
    Script locking_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
    result.push_back(locking_script);

    // p2sh-p2wpkh
    result.push_back(ScriptUtil::CreateP2shLockingScript(locking_script));
  }

  // p2pkh
  result.push_back(ScriptUtil::CreateP2pkhLockingScript(pubkey));

  // p2pk
  ScriptBuilder build;
  build.AppendData(pubkey);
  build.AppendOperator(ScriptOperator::OP_CHECKSIG);
  result.push_back(build.Build());

  return result;
}

uint32_t DescriptorNode::GetNeedArgumentNum() const {
  uint32_t result = need_arg_num_;
  if (!child_node_.empty()) {
    for (const auto& child : child_node_) {
      result += child.GetNeedArgumentNum();
    }
  }
  return result;
}

std::string DescriptorNode::ToString() const {
  std::string result;

  if (name_.empty()) {
    result = value_;
  }
  else if (child_node_.empty()) {
    result = name_ + "(" + value_ + ")";
  }
  else {
    result = name_ + "(";
    std::string child_text;
    for (const auto& child : child_node_) {
      if (!child_text.empty()) child_text += ",";
      child_text += child.ToString();
    }
    result += child_text + ")";
  }

  if ((depth_ == 0) && (!checksum_.empty())) {
    result += "#";
    result += checksum_;
  }
  return result;
}


// -----------------------------------------------------------------------------
// Descriptor
// -----------------------------------------------------------------------------
Descriptor::Descriptor() {
}

Descriptor Descriptor::Parse(
    const std::string& output_descriptor) {
  Descriptor desc;
  desc.root_node_ = DescriptorNode::Parse(output_descriptor);
  return desc;
}

bool Descriptor::IsComboScript() const {
  if (root_node_.GetScriptType() != DescriptorScriptType::kDescriptorScriptCombo) {
    return false;
  }
  return true;
}

uint32_t Descriptor::GetNeedArgumentNum() const {
  return root_node_.GetNeedArgumentNum();
}

Script Descriptor::GetScript() const {
  if (GetNeedArgumentNum() != 0) {
    // thrown
  }
  std::vector<std::string> list;
  return root_node_.GenerateScript(&list);
}

std::vector<Script> Descriptor::GetScriptCombo() const {
  std::vector<std::string> list;
  return GetScriptCombo(list);
}

std::vector<Script> Descriptor::GetScriptCombo(
    const std::vector<std::string>& array_argument) const {
  if (root_node_.GetScriptType() != DescriptorScriptType::kDescriptorScriptCombo) {
    // thrown
  }
  return root_node_.GetComboScript(array_argument);
}

Script Descriptor::GenerateScript(const std::string& argument) const {
  std::vector<std::string> list;
  for (uint32_t index=0; index<GetNeedArgumentNum(); ++index) {
    list.push_back(argument);
  }
  return GenerateScript(list);
}

Script Descriptor::GenerateScript(const std::vector<std::string>& array_argument) const {
  std::vector<std::string> copy_list = array_argument;
  return root_node_.GenerateScript(&copy_list);
}

DescriptorNode Descriptor::GetNode() const {
  return root_node_;
}

std::string ToString() const {
  return root_node_.ToString();
}

}  // namespace core
}  // namespace cfd
