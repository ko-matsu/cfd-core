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

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_descriptor.h"
#include "cfdcore/cfdcore_elements_address.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_script.h"

namespace cfd {
namespace core {

using logger::info;
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
    {"sortedmulti", DescriptorScriptType::kDescriptorScriptSortedMulti, false,
     true, true},
    {"addr", DescriptorScriptType::kDescriptorScriptAddr, true, false, false},
    {"raw", DescriptorScriptType::kDescriptorScriptRaw, true, false, false},
};

// -----------------------------------------------------------------------------
// DescriptorNode
// -----------------------------------------------------------------------------
DescriptorNode::DescriptorNode() {
  addr_prefixes_ = GetBitcoinAddressFormatList();
}

DescriptorNode::DescriptorNode(
    const std::vector<AddressFormatData>& network_parameters) {
  addr_prefixes_ = network_parameters;
}

DescriptorNode& DescriptorNode::operator=(const DescriptorNode& object) {
  name_ = object.name_;
  value_ = object.value_;
  key_info_ = object.key_info_;
  number_ = object.number_;
  child_node_ = object.child_node_;
  checksum_ = object.checksum_;
  depth_ = object.depth_;
  need_arg_num_ = object.need_arg_num_;
  node_type_ = object.node_type_;
  script_type_ = object.script_type_;
  key_type_ = object.key_type_;
  addr_prefixes_ = object.addr_prefixes_;
  return *this;
}

DescriptorNode DescriptorNode::Parse(
    const std::string& output_descriptor,
    const std::vector<AddressFormatData>& network_parameters) {
  DescriptorNode node(network_parameters);
  node.node_type_ = DescriptorNodeType::kDescriptorTypeScript;
  node.AnalyzeChild(output_descriptor, 0);
  node.AnalyzeAll("");
  // Script生成テスト
  // TODO 引数ありのパターン考慮必要
  node.GenerateScript(nullptr);
  return node;
}

void DescriptorNode::AnalyzeChild(
    const std::string& descriptor, uint32_t depth) {
  bool is_terminate = false;
  size_t offset = 0;
  uint32_t depth_work = depth;
  bool exist_child_node = false;
  bool checksum = false;
  depth_ = depth;
  std::string descriptor_main;
  info(CFD_LOG_SOURCE, "AnalyzeChild = {}", descriptor);

  for (size_t idx = 0; idx < descriptor.size(); ++idx) {
    const char& str = descriptor[idx];
    if (str == '#') {
      if (is_terminate) {
        checksum = true;
        offset = idx;
        checksum_ = descriptor.substr(idx + 1);
        descriptor_main = descriptor.substr(0, idx);
        if (checksum_.find("#") != std::string::npos) {
          warn(CFD_LOG_SOURCE, "Illegal data. Multiple '#' symbols.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError, "Multiple '#' symbols.");
        }
      } else {
        warn(CFD_LOG_SOURCE, "Illegal checksum data.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError, "Illegal checksum data.");
      }
    } else if (str == ',') {
      if (exist_child_node) {
        // through
        // warn(CFD_LOG_SOURCE, "Failed to exist child node after terminate.");
        // throw CfdException(
        //     CfdError::kCfdIllegalArgumentError, "Failed to exist child node after terminate.");
      } else if ((name_ == "multi") || (name_ == "sortedmulti")) {
        DescriptorNode node(addr_prefixes_);
        node.value_ = descriptor.substr(offset, idx - offset);
        if (child_node_.empty()) {
          node.node_type_ = DescriptorNodeType::kDescriptorTypeNumber;
          node.number_ = atoi(node.value_.c_str());
        } else {
          node.node_type_ = DescriptorNodeType::kDescriptorTypeKey;
        }
        node.depth_ = depth + 1;
        child_node_.push_back(node);
        offset = idx + 1;
      } else {
        warn(CFD_LOG_SOURCE, "Illegal command.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError, "Illegal command.");
      }
    } else if (str == ' ') {
      ++offset;
    } else if (str == '(') {
      if (depth_work == depth) {
        name_ = descriptor.substr(offset, idx - offset);
        offset = idx + 1;
      } else {
        exist_child_node = true;
      }
      info(
          CFD_LOG_SOURCE, "Target`(` depth_work={}, name={}", depth_work,
          name_);
      ++depth_work;
    } else if (str == ')') {
      --depth_work;
      info(CFD_LOG_SOURCE, "Target`)` depth_work = {}", depth_work);
      if (depth_work == depth) {
        value_ = descriptor.substr(offset, idx - offset);
        is_terminate = true;
        offset = idx + 1;
        if ((name_ == "addr") || (name_ == "raw")) {
          // do nothing
        } else {
          DescriptorNode node(addr_prefixes_);
          if (exist_child_node) {
            node.node_type_ = DescriptorNodeType::kDescriptorTypeScript;
            node.AnalyzeChild(value_, depth + 1);
            exist_child_node = false;
          } else {
            node.node_type_ = DescriptorNodeType::kDescriptorTypeKey;
            node.value_ = value_;
            node.depth_ = depth + 1;
          }
          child_node_.push_back(node);
          info(
              CFD_LOG_SOURCE, "Target`)` depth_work={}, child.value={}",
              depth_work, node.value_);
        }
      }
    }
  }

  if (name_.empty() || (name_ == "addr") || (name_ == "raw")) {
    // do nothing
  } else if (child_node_.empty()) {
    warn(CFD_LOG_SOURCE, "Failed to child node empty.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to child node empty.");
  }

  if (!descriptor_main.empty()) {
    CheckChecksum(descriptor_main);
  }
}

void DescriptorNode::CheckChecksum(const std::string& descriptor) {
  if (checksum_.size() != 8) {
    warn(
        CFD_LOG_SOURCE, "Expected 8 character checksum, not {} characters.",
        checksum_.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Expected 8 character checksum.");
  }
  std::string checksum = GenerateChecksum(descriptor);
  if (checksum.empty()) {
    warn(CFD_LOG_SOURCE, "Invalid characters in payload.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid characters in payload.");
  }
  if (checksum_ != checksum) {
    warn(
        CFD_LOG_SOURCE,
        "Provided checksum '{}' does not match computed checksum '{}'.",
        checksum_, checksum);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Unmatch checksum.");
  }
}

std::string DescriptorNode::GenerateChecksum(const std::string& descriptor) {
  // base
  // bitcoin/src/script/descriptor.cpp
  // std::string DescriptorChecksum(const Span<const char>& span)

  /** A character set designed such that:
   *  - The most common 'unprotected' descriptor characters (hex, keypaths) are in the first group of 32.
   *  - Case errors cause an offset that's a multiple of 32.
   *  - As many alphabetic characters are in the same group (while following the above restrictions).
   *
   * If p(x) gives the position of a character c in this character set, every group of 3 characters
   * (a,b,c) is encoded as the 4 symbols (p(a) & 31, p(b) & 31, p(c) & 31, (p(a) / 32) + 3 * (p(b) / 32) + 9 * (p(c) / 32).
   * This means that changes that only affect the lower 5 bits of the position, or only the higher 2 bits, will just
   * affect a single symbol.
   *
   * As a result, within-group-of-32 errors count as 1 symbol, as do cross-group errors that don't affect
   * the position within the groups.
   */
  static const std::string kInputCharset =
      "0123456789()[],'/*abcdefgh@:$%{}"
      "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
      "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

  /** The character set for the checksum itself (same as bech32). */
  static const std::string kChecksumCharset =
      "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

  static auto poly_mod = [](uint64_t c, int val) -> uint64_t {
    uint8_t c0 = c >> 35;
    c = ((c & 0x7ffffffff) << 5) ^ val;
    if (c0 & 1) c ^= 0xf5dee51989;
    if (c0 & 2) c ^= 0xa9fdca3312;
    if (c0 & 4) c ^= 0x1bab10e32d;
    if (c0 & 8) c ^= 0x3706b1677a;
    if (c0 & 16) c ^= 0x644d626ffd;
    return c;
  };

  uint64_t c = 1;
  int cls = 0;
  int clscount = 0;
  for (size_t idx = 0; idx < descriptor.size(); ++idx) {
    const char& ch = descriptor[idx];
    auto pos = kInputCharset.find(ch);
    if (pos == std::string::npos) return "";
    // Emit a symbol for the position inside the group, for every character.
    c = poly_mod(c, pos & 31);
    // Accumulate the group numbers
    cls = cls * 3 + static_cast<int>(pos >> 5);
    if (++clscount == 3) {
      // NOLINT Emit an extra symbol representing the group numbers, for every 3 characters.
      c = poly_mod(c, cls);
      cls = 0;
      clscount = 0;
    }
  }
  if (clscount > 0) c = poly_mod(c, cls);
  // Shift further to determine the checksum.
  for (int j = 0; j < 8; ++j) c = poly_mod(c, 0);
  // Prevent appending zeroes from not affecting the checksum.
  c ^= 1;

  std::string ret(8, ' ');
  for (int j = 0; j < 8; ++j)
    ret[j] = kChecksumCharset[(c >> (5 * (7 - j))) & 31];

  return ret;
}

void DescriptorNode::AnalyzeAll(const std::string& parent_name) {
  if (name_.empty()) {
    if (node_type_ == DescriptorNodeType::kDescriptorTypeNumber) {
      return;
    }
    // key analyze
    key_info_ = value_;
    if (value_[0] == '[') {
      // key origin information check
      // cut to ']'
      auto pos = value_.find("]");
      if (pos != std::string::npos) {
        key_info_ = value_.substr(pos + 1);
      }
    }
    // derive key check (xpub,etc)
    info(CFD_LOG_SOURCE, "key_info_ = {}", key_info_);
    std::string hdkey_top = key_info_.substr(0, 4);
    if ((hdkey_top == "xpub") || (hdkey_top == "tpub") ||
        (hdkey_top == "xprv") || (hdkey_top == "tprv")) {
      key_type_ = DescriptorKeyType::kDescriptorKeyBip32;
      if ((hdkey_top == "xprv") || (hdkey_top == "tprv")) {
        key_type_ = kDescriptorKeyBip32Priv;
      }
      if (key_info_.find("*") != std::string::npos) {
        need_arg_num_ = 1;
      }
      // FIXME HDKeyの実装
      key_info_ = key_info_;  // Keyクラスをserializeする
    } else {
      key_type_ = DescriptorKeyType::kDescriptorKeyPublic;
      bool is_wif = false;
      Pubkey pubkey;
      Privkey privkey;
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
        } else {
          throw except;
        }
      }
      if (is_wif) {
        // privkey WIF check
        try {
          privkey = Privkey::FromWif(key_info_, NetType::kMainnet);
        } catch (const CfdException& except) {
          std::string errmsg(except.what());
          if (errmsg.find("Error WIF to Private key.") == std::string::npos) {
            throw except;
          }
        }
        if (privkey.IsInvalid()) {
          try {
            privkey = Privkey::FromWif(key_info_, NetType::kTestnet);
          } catch (const CfdException& except) {
            std::string errmsg(except.what());
            if (errmsg.find("Error WIF to Private key.") ==
                std::string::npos) {
              throw except;
            }
          }
        }
        if (privkey.IsInvalid()) {
          warn(CFD_LOG_SOURCE, "Failed to privkey.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError, "privkey invalid.");
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
    warn(CFD_LOG_SOURCE, "Failed to unknown name.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to unknown name.");
  }

  if (p_data->top_only && (depth_ != 0)) {
    warn(CFD_LOG_SOURCE, "Failed to depth is not zero.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to depth is not zero.");
  }
  if (p_data->has_child) {
    if (child_node_.empty()) {
      warn(CFD_LOG_SOURCE, "Failed to child node empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Failed to child node empty.");
    }
  } else if (!child_node_.empty()) {
    warn(
        CFD_LOG_SOURCE, "Failed to child node num. size={}",
        child_node_.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to child node num.");
  }

  if (p_data->multisig) {
    if (child_node_.size() < 2) {
      warn(
          CFD_LOG_SOURCE, "Failed to multisig node low. size={}",
          child_node_.size());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Failed to multisig node low.");
    }
    if ((child_node_[0].number_ == 0) || (child_node_[0].number_ > 16) ||
        ((child_node_.size() - 1) <
         static_cast<size_t>(child_node_[0].number_))) {
      warn(
          CFD_LOG_SOURCE, "Failed to multisig require num. num={}",
          child_node_[0].number_);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to multisig require num.");
    }
    if ((child_node_.size() - 1) > 16) {
      warn(
          CFD_LOG_SOURCE, "Failed to multisig pubkey num. num={}",
          child_node_.size() - 1);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to multisig pubkey num.");
    }
    for (auto& child : child_node_) {
      child.AnalyzeAll(name_);
    }
    // TODO parentに応じて、Scriptサイズの確認が必要かもしれない。
    // TODO ただしparent_name_listの形じゃないと無理。
    // TODO 引数で入れるよりは、メンバ変数でParentのNodeポインタを持ったほうが楽そう。
#if 0
    script_type_ = p_data->type;
    Script script = GenerateScript(nullptr);
#endif
  } else if (name_ == "addr") {
    Address addr(value_, addr_prefixes_);
    info(CFD_LOG_SOURCE, "Address={}", addr.GetAddress());
  } else if (name_ == "raw") {
    Script script(value_);
    info(CFD_LOG_SOURCE, "script size={}", script.GetData().GetDataSize());
  } else if (child_node_.size() != 1) {
    warn(
        CFD_LOG_SOURCE, "Failed to child node num. size={}",
        child_node_.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to child node num.");
  } else {
    if ((name_ == "wsh") && (!parent_name.empty()) && (parent_name != "sh")) {
      warn(CFD_LOG_SOURCE, "Failed to wsh parent. only top or sh.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to wsh parent. only top or sh.");
    } else if ((name_ == "wpkh") && (parent_name == "wsh")) {
      warn(CFD_LOG_SOURCE, "Failed to wpkh parent. cannot wsh.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to wpkh parent. cannot wsh.");
    } else if (
        ((name_ == "wsh") || (name_ == "sh")) &&
        (child_node_[0].node_type_ !=
         DescriptorNodeType::kDescriptorTypeScript)) {
      warn(
          CFD_LOG_SOURCE,
          "Failed to sh child type. child is script only. nodetype={}",
          child_node_[0].node_type_);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to sh child type. child is script only.");
    } else if (
        (name_ != "wsh") && (name_ != "sh") &&
        (child_node_[0].node_type_ !=
         DescriptorNodeType::kDescriptorTypeKey)) {
      warn(
          CFD_LOG_SOURCE,
          "Failed to child type. child is key only. nodetype={}",
          child_node_[0].node_type_);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to child type. child is key only.");
    }
    child_node_[0].AnalyzeAll(name_);
  }
  script_type_ = p_data->type;
}

Script DescriptorNode::GenerateScript(
    std::vector<std::string>* array_argument,
    std::vector<Script>* script_list) const {
  ScriptBuilder build;
  Script locking_script;

  if (node_type_ == DescriptorNodeType::kDescriptorTypeKey) {
    Pubkey pubkey = GetPubkey(array_argument);
    build.AppendData(pubkey);
  } else if (node_type_ == DescriptorNodeType::kDescriptorTypeScript) {
    if (script_type_ == DescriptorScriptType::kDescriptorScriptRaw) {
      return Script(value_);
    } else if (script_type_ == DescriptorScriptType::kDescriptorScriptAddr) {
      Address addr(value_, addr_prefixes_);
      return addr.GetLockingScript();
    }
    if ((script_type_ == DescriptorScriptType::kDescriptorScriptMulti) ||
        (script_type_ == DescriptorScriptType::kDescriptorScriptSortedMulti)) {
      uint32_t reqnum = child_node_[0].number_;
      std::vector<Pubkey> pubkeys;
      for (size_t index = 1; index < child_node_.size(); ++index) {
        pubkeys.push_back(child_node_[index].GetPubkey(array_argument));
      }
      if (script_type_ == DescriptorScriptType::kDescriptorScriptSortedMulti) {
        // https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki
        std::sort(pubkeys.begin(), pubkeys.end(), Pubkey::IsLarge);
      }
      Script script = ScriptUtil::CreateMultisigRedeemScript(reqnum, pubkeys);
      if (script_list) script_list->push_back(script);
      return script;
    } else if (
        (script_type_ == DescriptorScriptType::kDescriptorScriptSh) ||
        (script_type_ == DescriptorScriptType::kDescriptorScriptWsh)) {
      Script script =
          child_node_[0].GenerateScript(array_argument, script_list);
      if (script_list && (!script.IsMultisigScript())) {
        script_list->push_back(script);
      }
      if (script_type_ == DescriptorScriptType::kDescriptorScriptWsh) {
        locking_script = ScriptUtil::CreateP2wshLockingScript(script);
      } else {
        locking_script = ScriptUtil::CreateP2shLockingScript(script);
      }
      return locking_script;
    }

    Pubkey pubkey = child_node_[0].GetPubkey(array_argument);
    if (script_type_ == DescriptorScriptType::kDescriptorScriptPk) {
      build.AppendData(pubkey);
      build.AppendOperator(ScriptOperator::OP_CHECKSIG);
    } else {
      if (script_type_ == DescriptorScriptType::kDescriptorScriptCombo) {
        if (pubkey.IsCompress()) {
          // p2wpkh
          locking_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
        } else {
          // p2pkh
          locking_script = ScriptUtil::CreateP2pkhLockingScript(pubkey);
        }
      } else if (script_type_ == DescriptorScriptType::kDescriptorScriptPkh) {
        locking_script = ScriptUtil::CreateP2pkhLockingScript(pubkey);
      } else if (script_type_ == DescriptorScriptType::kDescriptorScriptWpkh) {
        locking_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
      }
      return locking_script;
    }
  } else if (node_type_ == DescriptorNodeType::kDescriptorTypeNumber) {
    ScriptElement elem(static_cast<int64_t>(number_));
    build.AppendElement(elem);
  } else {
    // do nothing
  }
  return build.Build();
}

Pubkey DescriptorNode::GetPubkey(
    std::vector<std::string>* array_argument) const {
  Pubkey pubkey;
  if (key_type_ == DescriptorKeyType::kDescriptorKeyPublic) {
    pubkey = Pubkey(key_info_);
  } else if (need_arg_num_ == 0) {
    // FIXME HDkey
    // 指定キー
    // 強化鍵の場合、xprv/tprvの必要あり
  } else {
    if (array_argument && array_argument->empty()) {
      warn(CFD_LOG_SOURCE, "Failed to generate pubkey from hdkey.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to generate pubkey from hdkey.");
    }
    // FIXME HDkey
    // 動的キー生成。文字列からパス一覧を生成する必要あり。
    // 強化鍵の場合、xprv/tprvの必要あり
    // array_argumentがnullptrの場合、仮で0を設定する。（生成テスト用）
  }

  if (!pubkey.IsValid()) {
    warn(CFD_LOG_SOURCE, "Failed to pubkey.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to pubkey data.");
  }
  return pubkey;
}

std::vector<Script> DescriptorNode::GenerateScriptAll(
    std::vector<std::string>* array_argument) const {
  if (script_type_ != DescriptorScriptType::kDescriptorScriptCombo) {
    // warn(CFD_LOG_SOURCE, "Illegal node. only `combo`.");
    // throw CfdException(
    //     CfdError::kCfdIllegalArgumentError, "Illegal node. only `combo`.");
    return std::vector<Script>{GenerateScript(array_argument)};
  }
  if (child_node_.empty()) {
    warn(CFD_LOG_SOURCE, "Failed to child node empty.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to child node empty.");
  }
  std::vector<Script> result;
  Pubkey pubkey = child_node_[0].GetPubkey(array_argument);

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

std::string DescriptorNode::ToString(bool append_checksum) const {
  std::string result;
  info(CFD_LOG_SOURCE, "name={}, value={}", name_, value_);

  if (name_.empty()) {
    result = value_;
  } else if (child_node_.empty()) {
    result = name_ + "(" + value_ + ")";
  } else {
    result = name_ + "(";
    std::string child_text;
    for (const auto& child : child_node_) {
      if (!child_text.empty()) child_text += ",";
      child_text += child.ToString();
    }
    result += child_text + ")";
  }

  if ((depth_ == 0) && append_checksum) {
    std::string checksum = GenerateChecksum(result);
    if (!checksum.empty()) {
      result += "#";
      result += checksum;
    }
  }
  return result;
}

// -----------------------------------------------------------------------------
// Descriptor
// -----------------------------------------------------------------------------
Descriptor::Descriptor() {}

Descriptor Descriptor::Parse(
    const std::string& output_descriptor,
    const std::vector<AddressFormatData>* network_parameters) {
  std::vector<AddressFormatData> network_pefixes;
  if (network_parameters) {
    network_pefixes = *network_parameters;
  } else {
    network_pefixes = GetBitcoinAddressFormatList();
  }
  Descriptor desc;
  desc.root_node_ = DescriptorNode::Parse(output_descriptor, network_pefixes);
  return desc;
}

#ifndef CFD_DISABLE_ELEMENTS
Descriptor Descriptor::ParseElements(const std::string& output_descriptor) {
  std::vector<AddressFormatData> network_pefixes =
      GetElementsAddressFormatList();
  return Parse(output_descriptor, &network_pefixes);
}
#endif  // CFD_DISABLE_ELEMENTS

bool Descriptor::IsComboScript() const {
  if (root_node_.GetScriptType() !=
      DescriptorScriptType::kDescriptorScriptCombo) {
    return false;
  }
  return true;
}

uint32_t Descriptor::GetNeedArgumentNum() const {
  return root_node_.GetNeedArgumentNum();
}

Script Descriptor::GetScript(std::vector<Script>* script_list) const {
  if (GetNeedArgumentNum() != 0) {
    warn(CFD_LOG_SOURCE, "Failed to empty argument.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to empty argument. need argument descriptor.");
  }
  std::vector<std::string> list;
  return root_node_.GenerateScript(&list, script_list);
}

std::vector<Script> Descriptor::GetScriptCombo() const {
  std::vector<std::string> list;
  return GetScriptCombo(list);
}

std::vector<Script> Descriptor::GetScriptCombo(
    const std::vector<std::string>& array_argument) const {
  if (root_node_.GetScriptType() !=
      DescriptorScriptType::kDescriptorScriptCombo) {
    warn(CFD_LOG_SOURCE, "Illegal node. only `combo`.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Illegal node. only `combo`.");
  }
  std::vector<std::string> list = array_argument;
  return root_node_.GenerateScriptAll(&list);
}

Script Descriptor::GenerateScript(
    const std::string& argument, std::vector<Script>* script_list) const {
  std::vector<std::string> list;
  for (uint32_t index = 0; index < GetNeedArgumentNum(); ++index) {
    list.push_back(argument);
  }
  return GenerateScript(list, script_list);
}

Script Descriptor::GenerateScript(
    const std::vector<std::string>& array_argument,
    std::vector<Script>* script_list) const {
  std::vector<std::string> copy_list = array_argument;
  return root_node_.GenerateScript(&copy_list, script_list);
}

DescriptorNode Descriptor::GetNode() const { return root_node_; }

std::string Descriptor::ToString(bool append_checksum) const {
  return root_node_.ToString(append_checksum);
}

}  // namespace core
}  // namespace cfd
