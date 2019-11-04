// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_descriptor.h
 *
 * @brief Script関連クラス定義
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_DESCRIPTOR_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_DESCRIPTOR_H_

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"

namespace cfd {
namespace core {


enum DescriptorNodeType {
  kDescriptorTypeNull,
  kDescriptorTypeScript,
  kDescriptorTypeKey,
  kDescriptorTypeNumber,
}

enum DescriptorScriptType {
  kDescriptorScriptNull,
  kDescriptorScriptSh,
  kDescriptorScriptWsh,
  kDescriptorScriptPk,
  kDescriptorScriptPkh,
  kDescriptorScriptWpkh,
  kDescriptorScriptCombo,
  kDescriptorScriptMulti,
  kDescriptorScriptSortedMulti,
  kDescriptorScriptAddr,
  kDescriptorScriptRaw,
}

enum DescriptorKeyType {
  kDescriptorKeyNull,
  kDescriptorKeyPublic,
  kDescriptorKeyBip32,
  kDescriptorKeyBip32Priv,
}


class CFD_CORE_EXPORT DescriptorNode {
 public:
  DescriptorNode();

  static DescriptorNode Parse(const std::string& output_descriptor);

  Script GenerateScript() const;
  Script GenerateScript(std::vector<std::string>* array_argument) const;
  std::vector<Script> GetComboScript(std::vector<std::string>* array_argument) const;
  uint32_t GetNeedArgumentNum() const;
  std::string ToString() const;

  DescriptorNodeType GetNodeType() const { return node_type_; }
  DescriptorScriptType GetScriptType() const { return script_type_; }

 protected:
  Pubkey GetPubkey(std::vector<std::string>* array_argument);

 private:
  std::string name_;
  std::string value_;
  std::string key_info_;
  uint32_t number_ = 0;
  std::vector<DescriptorNode> child_node_;
  std::string checksum_;
  uint32_t depth_ = 0;
  uint32_t need_arg_num_ = 0;
  DescriptorNodeType node_type_;
  DescriptorScriptType script_type_;
  DescriptorKeyType key_type_;
}

class CFD_CORE_EXPORT Descriptor
{
 public:
  static Descriptor Parse(const std::string& output_descriptor);

  Descriptor();

  bool IsComboScript() const;
  uint32_t GetNeedArgumentNum() const;

  Script GetScript() const;   // GetNeedArgumentNum == 0
  std::vector<Script> GetScriptCombo() const;   // IsComboScript == true
  std::vector<Script> GetScriptCombo(const std::vector<std::string>& array_argument) const;   // IsComboScript == true
  // Pubkeyが圧縮されていない場合、セットにはP2PKおよびP2PKHスクリプトのみが含まれます。

  /**
   * 複数の引数がある場合、同じ内容を一括指定する。
   */
  Script GenerateScript(const std::string& argument) const;
  Script GenerateScript(const std::vector<std::string>& array_argument) const;

  DescriptorNode GetNode() const;
  std::string ToString() const;

  // チェックサムの確認

 private:
  DescriptorNode root_node_;
}

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_DESCRIPTOR_H_
