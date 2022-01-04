// Copyright 2020 CryptoGarage
/**
 * @file cfdcore_key.cpp
 *
 * @brief definition for Pubkey/Privkey class
 */

#include "cfdcore/cfdcore_key.h"

#include <map>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_transaction_common.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT
#include "univalue.h"            // NOLINT

namespace cfd {
namespace core {

using logger::warn;

// ----------------------------------------------------------------------------
// Global API
// ----------------------------------------------------------------------------
//! key format list
const std::vector<KeyFormatData> kDefaultKeyFormatList = {
    KeyFormatData(true), KeyFormatData(false)};
//! custom bitcoin address format list
static std::vector<KeyFormatData> g_custom_key_format_list;

std::vector<KeyFormatData> GetKeyFormatList() {
  if (!g_custom_key_format_list.empty()) {
    return g_custom_key_format_list;
  }
  return kDefaultKeyFormatList;
}

KeyFormatData GetKeyFormatData(NetType net_type) {
  bool is_mainnet =
      ((net_type == NetType::kMainnet) || (net_type == NetType::kLiquidV1));
  return GetKeyFormatData(is_mainnet);
}

KeyFormatData GetKeyFormatData(bool is_mainnet) {
  const auto plist = (g_custom_key_format_list.empty())
                         ? &kDefaultKeyFormatList
                         : &g_custom_key_format_list;
  for (const KeyFormatData &data : *plist) {
    if (data.IsMainnet() == is_mainnet) return data;
  }
  throw CfdException(
      CfdError::kCfdInternalError, "invalid key format management.");
}

void SetCustomKeyFormatList(const std::vector<KeyFormatData> &list) {
  if ((!list.empty()) && g_custom_key_format_list.empty()) {
    bool is_added_mainnet = false;
    bool is_added_testnet = false;
    for (KeyFormatData item : list) {
      if (!item.LoadCache()) {
        // invalid data
      } else if (item.IsMainnet()) {
        if (!is_added_mainnet) {
          g_custom_key_format_list.emplace_back(item);
          is_added_mainnet = true;
        }
      } else if (!is_added_testnet) {
        g_custom_key_format_list.emplace_back(item);
        is_added_testnet = true;
      }
    }

    if (!is_added_mainnet) {
      g_custom_key_format_list.emplace_back(KeyFormatData(true));
    }
    if (!is_added_testnet) {
      g_custom_key_format_list.emplace_back(KeyFormatData(false));
    }
  }
}

void ClearCustomKeyFormatList() { g_custom_key_format_list.clear(); }

// ----------------------------------------------------------------------------
// KeyFormatData
// ----------------------------------------------------------------------------
//! format list
static const Bip32FormatType kFormatTypeList[] = {
    // TODO(k-matsuzawa): The vector was not yet initialized when using
    // this variable. Therefore, it is defined in an array.
    Bip32FormatType::kNormal,
    Bip32FormatType::kBip49,
    Bip32FormatType::kBip84,
};
//! format list count.
static const size_t kFormatTypeListNum =
    sizeof(kFormatTypeList) / sizeof(Bip32FormatType);

KeyFormatData::KeyFormatData() : map_(), has_format_(kFormatTypeListNum) {}

KeyFormatData::KeyFormatData(bool is_mainnet_on_default)
    : map_(), has_format_(kFormatTypeListNum) {
  if (is_mainnet_on_default) {
    map_.emplace(kKeytypeIsMainnet, "true");
    map_.emplace(kWifPrefix, "80");
    map_.emplace(kBip32Xpub, "0488b21e");
    map_.emplace(kBip32Xprv, "0488ade4");
    map_.emplace(kBip49Ypub, "049d7cb2");
    map_.emplace(kBip49Yprv, "049d7878");
    map_.emplace(kBip84Zpub, "04b24746");
    map_.emplace(kBip84Zprv, "04b2430c");
  } else {
    map_.emplace(kKeytypeIsMainnet, "false");
    map_.emplace(kWifPrefix, "ef");
    map_.emplace(kBip32Xpub, "043587cf");
    map_.emplace(kBip32Xprv, "04358394");
    map_.emplace(kBip49Ypub, "044a5262");
    map_.emplace(kBip49Yprv, "044a4e28");
    map_.emplace(kBip84Zpub, "045f1cf6");
    map_.emplace(kBip84Zprv, "045f18bc");
  }
  LoadCache();
}

KeyFormatData::KeyFormatData(
    const std::map<std::string, std::string> &map_data)
    : map_(map_data), has_format_(kFormatTypeListNum) {}

KeyFormatData::KeyFormatData(const KeyFormatData &object) {
  map_ = object.map_;
  is_mainnet = object.is_mainnet;
  wif_prefix_ = object.wif_prefix_;
  has_format_ = object.has_format_;
  bip32_ = object.bip32_;
  bip49_ = object.bip49_;
  bip84_ = object.bip84_;
}

KeyFormatData &KeyFormatData::operator=(const KeyFormatData &object) {
  if (this != &object) {
    map_ = object.map_;
    is_mainnet = object.is_mainnet;
    wif_prefix_ = object.wif_prefix_;
    has_format_ = object.has_format_;
    bip32_ = object.bip32_;
    bip49_ = object.bip49_;
    bip84_ = object.bip84_;
  }
  return *this;
}

bool KeyFormatData::IsFind(const std::string &key) const {
  return map_.find(key) != map_.end();
}

std::string KeyFormatData::GetString(const std::string &key) const {
  if (map_.find(key) == map_.end()) {
    throw CfdException(
        CfdError::kCfdOutOfRangeError, "unknown key. key=" + key);
  }
  return map_.at(key);
}

uint32_t KeyFormatData::GetValue(const std::string &key) const {
  if (map_.find(key) == map_.end()) {
    throw CfdException(
        CfdError::kCfdOutOfRangeError, "unknown key. key=" + key);
  }
  return std::stoi(map_.at(key), nullptr, 16);
}

uint32_t KeyFormatData::GetWifPrefix() const { return wif_prefix_; }

ExtkeyVersionPair KeyFormatData::GetVersionPair(uint32_t version) const {
  return GetVersionPair(GetVersionFormatType(version));
}

ExtkeyVersionPair KeyFormatData::GetVersionPair(
    Bip32FormatType format_type) const {
  switch (format_type) {
    case kNormal:
      return bip32_;
    case kBip49:
      return bip49_;
    case kBip84:
      return bip84_;
    default:
      throw CfdException(
          CfdError::kCfdOutOfRangeError, "unknown format type.");
  }
}

Bip32FormatType KeyFormatData::GetVersionFormatType(uint32_t version) const {
  std::vector<const ExtkeyVersionPair *> cache_list = {
      &bip32_, &bip49_, &bip84_};
  for (const auto &type : kFormatTypeList) {
    if (has_format_[type]) {
      if ((cache_list[type]->pubkey_version == version) ||
          (cache_list[type]->privkey_version == version)) {
        return type;
      }
    }
  }
  throw CfdException(CfdError::kCfdIllegalArgumentError, "unknown version.");
}

bool KeyFormatData::IsFindVersion(uint32_t version) const {
  std::vector<const ExtkeyVersionPair *> cache_list = {
      &bip32_, &bip49_, &bip84_};
  for (const auto &type : kFormatTypeList) {
    if (has_format_[type]) {
      if ((cache_list[type]->pubkey_version == version) ||
          (cache_list[type]->privkey_version == version)) {
        return true;
      }
    }
  }
  return false;
}

bool KeyFormatData::IsFindFormatType(Bip32FormatType format_type) const {
  switch (format_type) {
    case kNormal:
    case kBip49:
    case kBip84:
      return (has_format_[format_type]);
    default:
      return false;
  }
}

NetType KeyFormatData::GetNetType() const {
  return (is_mainnet) ? NetType::kMainnet : NetType::kTestnet;
}

bool KeyFormatData::IsMainnet() const { return is_mainnet; }

bool KeyFormatData::IsValid() const {
  static const std::vector<const char *> key_list = {
      kWifPrefix, kBip32Xpub, kBip32Xprv};
  for (const char *key : key_list) {
    if (map_.find(key) == map_.end()) return false;
  }
  try {
    auto wif = ByteData(map_.find(kWifPrefix)->second);
    if (wif.GetDataSize() != 1) return false;
    auto xpub = ByteData(map_.find(kBip32Xpub)->second);
    if (xpub.GetDataSize() != 4) return false;
    auto xprv = ByteData(map_.find(kBip32Xprv)->second);
    if (xprv.GetDataSize() != 4) return false;
    if ((map_.find(kBip49Ypub) != map_.end()) &&
        (map_.find(kBip49Yprv) != map_.end())) {
      auto ypub = ByteData(map_.find(kBip49Ypub)->second);
      if (ypub.GetDataSize() != 4) return false;
      auto yprv = ByteData(map_.find(kBip49Yprv)->second);
      if (yprv.GetDataSize() != 4) return false;
    }
    if ((map_.find(kBip84Zpub) != map_.end()) &&
        (map_.find(kBip84Zprv) != map_.end())) {
      auto zpub = ByteData(map_.find(kBip84Zpub)->second);
      if (zpub.GetDataSize() != 4) return false;
      auto zprv = ByteData(map_.find(kBip84Zprv)->second);
      if (zprv.GetDataSize() != 4) return false;
    }
  } catch (const CfdException &) {
    return false;
  }
  return true;
}

bool KeyFormatData::LoadCache() {
  static const auto func = [](const std::string &buf) -> uint32_t {
    if (buf.size() != 8) {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Invalid extkey version.");
    }
    Deserializer dec = Deserializer(ByteData(buf));
    return dec.ReadUint32FromBigEndian();
  };

  if (!IsValid()) return false;

  // reset value
  has_format_.clear();
  has_format_.resize(kFormatTypeListNum);
  is_mainnet = false;
  wif_prefix_ = 0;

  if (map_.find(kKeytypeIsMainnet) != map_.end()) {
    auto flag_str = StringUtil::ToLower(map_.find(kKeytypeIsMainnet)->second);
    is_mainnet = (flag_str.empty() || (flag_str == "true"));
  }
  wif_prefix_ = ByteData(map_.find(kWifPrefix)->second).GetHeadData();
  bip32_.pubkey_version = func(map_.find(kBip32Xpub)->second);
  bip32_.privkey_version = func(map_.find(kBip32Xprv)->second);
  has_format_.at(Bip32FormatType::kNormal) = true;
  if ((map_.find(kBip49Ypub) != map_.end()) &&
      (map_.find(kBip49Yprv) != map_.end())) {
    bip49_.pubkey_version = func(map_.find(kBip49Ypub)->second);
    bip49_.privkey_version = func(map_.find(kBip49Yprv)->second);
    has_format_.at(Bip32FormatType::kBip49) = true;
  }
  if ((map_.find(kBip84Zpub) != map_.end()) &&
      (map_.find(kBip84Zprv) != map_.end())) {
    bip84_.pubkey_version = func(map_.find(kBip84Zpub)->second);
    bip84_.privkey_version = func(map_.find(kBip84Zprv)->second);
    has_format_.at(Bip32FormatType::kBip84) = true;
  }
  return true;
}

KeyFormatData KeyFormatData::ConvertFromJson(const std::string &json_data) {
  UniValue object;
  object.read(json_data);
  std::map<std::string, std::string> prefix_map;
  if (object.isObject() && object.exists(kBip32Xpub)) {
    std::map<std::string, UniValue> json_map;
    object.getObjMap(json_map);
    for (const auto &child : json_map) {
      if (child.second.isStr()) {
        prefix_map.emplace(child.first, child.second.getValStr());
      }
    }
  }
  if (prefix_map.empty() || (prefix_map.size() == 0)) {
    throw CfdException(
        kCfdIllegalArgumentError, "Invalid key prefix json data.");
  }
  KeyFormatData result(prefix_map);
  return result;
}

std::vector<KeyFormatData> KeyFormatData::ConvertListFromJson(
    const std::string &json_data) {
  UniValue object;
  object.read(json_data);
  std::vector<KeyFormatData> result;
  if (object.isArray()) {
    for (const auto &element : object.getValues()) {
      if (element.isObject() && element.exists(kBip32Xpub)) {
        std::map<std::string, std::string> prefix_map;
        std::map<std::string, UniValue> json_map;
        element.getObjMap(json_map);
        for (const auto &child : json_map) {
          if (child.second.isStr()) {
            prefix_map.emplace(child.first, child.second.getValStr());
          }
        }
        if ((!prefix_map.empty()) && (prefix_map.size() != 0)) {
          result.emplace_back(prefix_map);
        }
      }
    }
  }
  if (result.empty()) {
    throw CfdException(
        kCfdIllegalArgumentError, "Invalid key prefix json data.");
  }
  return result;
}

// ----------------------------------------------------------------------------
// Public Key
// ----------------------------------------------------------------------------
Pubkey::Pubkey() : data_() {}

bool Pubkey::IsValid(const ByteData &byte_data) {
  const std::vector<uint8_t> &buffer = byte_data.GetBytes();
  if (buffer.size() > 0) {
    uint8_t header = buffer[0];
    if (header == 0x02 || header == 0x03) {
      return buffer.size() == Pubkey::kCompressedPubkeySize;
    } else if (header == 0x04 || header == 0x06 || header == 0x07) {
      return buffer.size() == Pubkey::kPubkeySize;
    }
  }
  return false;
}

Pubkey::Pubkey(ByteData byte_data) : data_(byte_data) {
  if (!Pubkey::IsValid(data_)) {
    warn(CFD_LOG_SOURCE, "Invalid Pubkey data. hex={}.", data_.GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Pubkey data.");
  }
}

Pubkey::Pubkey(const std::string &hex_string) : Pubkey(ByteData(hex_string)) {
  // do nothing
}

std::string Pubkey::GetHex() const { return data_.GetHex(); }

ByteData Pubkey::GetData() const { return data_.GetBytes(); }

bool Pubkey::IsCompress() const {
  if (!data_.IsEmpty()) {
    uint8_t header = data_.GetHeadData();
    if (header == 0x02 || header == 0x03) {
      return true;
    } else if (header == 0x04 || header == 0x06 || header == 0x07) {
      return false;
    }
  }
  return false;
}

bool Pubkey::IsParity() const { return (data_.GetHeadData() == 0x03); }

bool Pubkey::IsValid() const { return IsValid(data_); }

bool Pubkey::Equals(const Pubkey &pubkey) const {
  return data_.Equals(pubkey.data_);
}

ByteData Pubkey::GetFingerprint(uint32_t get_size) const {
  if ((get_size == 0) || (get_size > kByteData160Length)) {
    warn(CFD_LOG_SOURCE, "Invalid fingerprint size: {}.", get_size);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid fingerprint size.");
  }

  ByteData data;
  if (IsCompress()) {
    data = data_;
  } else {
    data = Compress().data_;
  }
  auto data160 = HashUtil::Hash160(data);
  auto bytes = data160.GetBytes();
  return ByteData(bytes.data(), get_size);
}

Pubkey Pubkey::CombinePubkey(const std::vector<Pubkey> &pubkeys) {
  std::vector<ByteData> data_list;
  for (const auto &pubkey : pubkeys) {
    data_list.push_back(pubkey.GetData());
  }
  return Pubkey(WallyUtil::CombinePubkeySecp256k1Ec(data_list));
}

Pubkey Pubkey::CombinePubkey(const Pubkey &pubkey, const Pubkey &message_key) {
  std::vector<ByteData> data_list;
  data_list.push_back(pubkey.GetData());
  data_list.push_back(message_key.GetData());

  return Pubkey(WallyUtil::CombinePubkeySecp256k1Ec(data_list));
}

Pubkey Pubkey::CreateTweakAdd(const ByteData256 &tweak) const {
  ByteData tweak_added = WallyUtil::AddTweakPubkey(data_, tweak);
  return Pubkey(tweak_added);
}

Pubkey Pubkey::CreateTweakMul(const ByteData256 &tweak) const {
  ByteData tweak_muled = WallyUtil::MulTweakPubkey(data_, tweak);
  return Pubkey(tweak_muled);
}

Pubkey Pubkey::CreateNegate() const {
  ByteData negated = WallyUtil::NegatePubkey(data_);
  return Pubkey(negated);
}

Pubkey Pubkey::Compress() const {
  if (IsCompress()) {
    return *this;
  }

  ByteData compress_data = WallyUtil::CompressPubkey(data_);
  return Pubkey(compress_data);
}

Pubkey Pubkey::Uncompress() const {
  if (!IsCompress()) {
    return *this;
  }

  // The conversion from uncompress to compress is irreversible.
  // (if convert compress to uncompress, prefix is '04'. Not '06' or '07'.)
  std::vector<uint8_t> decompress_data(EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
  std::vector<uint8_t> data = data_.GetBytes();
  int ret = wally_ec_public_key_decompress(
      data.data(), data.size(), decompress_data.data(),
      decompress_data.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_ec_public_key_decompress error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to uncompress pubkey.");
  }
  return Pubkey(decompress_data);
}

bool Pubkey::IsLarge(const Pubkey &source, const Pubkey &destination) {
  return ByteData::IsLarge(source.data_, destination.data_);
}

bool Pubkey::VerifyEcSignature(
    const ByteData256 &signature_hash, const ByteData &signature) const {
  return SignatureUtil::VerifyEcSignature(signature_hash, *this, signature);
}

Pubkey Pubkey::operator+=(const Pubkey &right) {
  Pubkey key = Pubkey::CombinePubkey(*this, right);
  *this = key;
  return *this;
}

Pubkey Pubkey::operator+=(const ByteData256 &right) {
  Pubkey key = CreateTweakAdd(right);
  *this = key;
  return *this;
}

Pubkey Pubkey::operator-=(const ByteData256 &right) {
  Privkey sk(right);
  auto neg = sk.CreateNegate();
  Pubkey key = CreateTweakAdd(ByteData256(neg.GetData()));
  *this = key;
  return *this;
}

Pubkey Pubkey::operator*=(const ByteData256 &right) {
  Pubkey key = CreateTweakMul(right);
  *this = key;
  return *this;
}

// global operator overloading
Pubkey operator+(const Pubkey &left, const Pubkey &right) {
  return Pubkey::CombinePubkey(left, right);
}

Pubkey operator+(const Pubkey &left, const ByteData256 &right) {
  return left.CreateTweakAdd(right);
}

Pubkey operator-(const Pubkey &left, const ByteData256 &right) {
  Pubkey key = left;
  key -= right;
  return key;
}

Pubkey operator*(const Pubkey &left, const ByteData256 &right) {
  return left.CreateTweakMul(right);
}

// ----------------------------------------------------------------------------
// Private Key
// ----------------------------------------------------------------------------
/// Mainnet Prefix
static constexpr uint32_t kPrefixMainnet = 0x80;
/// Testnet Prefix
static constexpr uint32_t kPrefixTestnet = 0xef;

Privkey::Privkey() : data_() {
  // do nothing
}

Privkey::Privkey(
    const ByteData &byte_data, NetType net_type, bool is_compressed)
    : data_(byte_data), is_compressed_(is_compressed), net_type_(net_type) {
  if (!IsValid(data_.GetBytes())) {
    warn(CFD_LOG_SOURCE, "Invalid Privkey data. hex={}.", data_.GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Privkey data.");
  }
}

Privkey::Privkey(
    const ByteData256 &byte_data, NetType net_type, bool is_compressed)
    : data_(ByteData(byte_data.GetBytes())),
      is_compressed_(is_compressed),
      net_type_(net_type) {
  if (!IsValid(data_.GetBytes())) {
    warn(CFD_LOG_SOURCE, "Invalid Privkey data. hex={}.", data_.GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Privkey data.");
  }
}

Privkey::Privkey(
    const std::string &hex_str, NetType net_type, bool is_compressed)
    : data_(ByteData(hex_str)),
      is_compressed_(is_compressed),
      net_type_(net_type) {
  if (!IsValid(data_.GetBytes())) {
    warn(CFD_LOG_SOURCE, "Invalid Privkey data. hex={}.", data_.GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Privkey data.");
  }
}

std::string Privkey::GetHex() const { return data_.GetHex(); }

ByteData Privkey::GetData() const { return data_.GetBytes(); }

std::string Privkey::ConvertWif(NetType net_type, bool is_compressed) const {
  auto format_data = GetKeyFormatData(net_type);
  uint32_t prefix = format_data.GetWifPrefix();
  uint32_t flags =
      (is_compressed ? WALLY_WIF_FLAG_COMPRESSED
                     : WALLY_WIF_FLAG_UNCOMPRESSED);
  char *wif_ptr = NULL;

  int ret = wally_wif_from_bytes(
      data_.GetBytes().data(), data_.GetDataSize(), prefix, flags, &wif_ptr);
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_wif_from_bytes error. ret={} bytes={}.", ret,
        data_.GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Error Private key to WIF.");
  }
  std::string wif = WallyUtil::ConvertStringAndFree(wif_ptr);
  return wif;
}

std::string Privkey::GetWif() const {
  return ConvertWif(net_type_, is_compressed_);
}

Privkey Privkey::FromWif(
    const std::string &wif, NetType net_type, bool is_compressed) {
  std::vector<uint8_t> privkey(kPrivkeySize);
  NetType temp_net_type = net_type;
  bool is_temp_compressed = is_compressed;
  if (net_type == NetType::kCustomChain) {
    // auto analyze
    size_t written = 0;
    size_t uncompressed = 0;
    std::vector<uint8_t> buf(2 + EC_PRIVATE_KEY_LEN + BASE58_CHECKSUM_LEN);
    int ret = wally_base58_to_bytes(
        wif.data(), BASE58_FLAG_CHECKSUM, buf.data(), buf.size(), &written);
    if (ret != WALLY_OK) {
      warn(
          CFD_LOG_SOURCE, "wally_base58_to_bytes error. ret={} wif={}.", ret,
          wif);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Error decode base58 WIF.");
    }
    ret = wally_wif_is_uncompressed(wif.data(), &uncompressed);
    if (ret != WALLY_OK) {
      warn(
          CFD_LOG_SOURCE, "wally_wif_is_uncompressed error. ret={} wif={}.",
          ret, wif);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Error WIF is uncompressed.");
    }

    uint32_t prefix = buf[0];
    memcpy(privkey.data(), &buf[1], privkey.size());

    bool has_prefix = false;
    for (const auto &format : GetKeyFormatList()) {
      if (format.GetWifPrefix() == prefix) {
        temp_net_type = format.GetNetType();
        has_prefix = true;
        break;
      }
    }
    if (!has_prefix) {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parse WIF. unsupported WIF prefix.");
    }
    is_temp_compressed = (uncompressed == 0) ? true : false;
  } else {
    auto format_data = GetKeyFormatData(net_type);
    uint32_t prefix = format_data.GetWifPrefix();
    uint32_t flags =
        (is_compressed ? WALLY_WIF_FLAG_COMPRESSED
                       : WALLY_WIF_FLAG_UNCOMPRESSED);

    int ret = wally_wif_to_bytes(
        wif.data(), prefix, flags, privkey.data(), kPrivkeySize);
    if (ret != WALLY_OK) {
      warn(
          CFD_LOG_SOURCE, "wally_wif_to_bytes error. ret={} wif={}.", ret,
          wif);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Error WIF to Private key.");
    }
    temp_net_type = net_type;
    is_temp_compressed = is_compressed;
  }

  if (!IsValid(privkey)) {
    warn(
        CFD_LOG_SOURCE, "Invalid Privkey data. data={}",
        ByteData(privkey).GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Privkey data");
  }
  Privkey key = Privkey(ByteData(privkey));
  key.SetPubkeyCompressed(is_temp_compressed);
  key.SetNetType(temp_net_type);
  return key;
}

bool Privkey::HasWif(
    const std::string &wif, NetType *net_type, bool *is_compressed) {
  static constexpr size_t kWifMinimumSize = EC_PRIVATE_KEY_LEN + 1;

  size_t is_uncompressed = 0;
  int ret = wally_wif_is_uncompressed(wif.c_str(), &is_uncompressed);
  if (ret != WALLY_OK) {
    // contains check wif.
    return false;
  }

  bool has_wif = false;
  ByteData data = CryptoUtil::DecodeBase58Check(wif);
  if (data.GetDataSize() >= kWifMinimumSize) {
    std::vector<uint8_t> key_data = data.GetBytes();
    uint32_t prefix = key_data[0];

    if (net_type != nullptr) {
      bool has_prefix = false;
      for (const auto &format : GetKeyFormatList()) {
        if (format.GetWifPrefix() == prefix) {
          *net_type = format.GetNetType();
          has_prefix = true;
          break;
        }
      }
      if (!has_prefix) {
        warn(CFD_LOG_SOURCE, "Invalid Privkey format. prefix={}", prefix);
        *net_type = NetType::kTestnet;
      }
    }

    if (is_compressed != nullptr) {
      *is_compressed = (is_uncompressed == 0) ? true : false;
    }
    has_wif = true;
  }
  return has_wif;
}

Pubkey Privkey::GetPubkey() const { return GeneratePubkey(is_compressed_); }

Pubkey Privkey::GeneratePubkey(bool is_compressed) const {
  std::vector<uint8_t> pubkey(Pubkey::kCompressedPubkeySize);
  int ret = wally_ec_public_key_from_private_key(
      data_.GetBytes().data(), data_.GetDataSize(), pubkey.data(),
      pubkey.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE,
        "wally_ec_public_key_from_private_key error. ret={} privkey={}.", ret,
        data_.GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Generate Pubkey error.");
  }
  if (is_compressed) {
    return Pubkey(pubkey);
  }

  std::vector<uint8_t> uncompressed_pubkey(Pubkey::kPubkeySize);
  ret = wally_ec_public_key_decompress(
      pubkey.data(), pubkey.size(), uncompressed_pubkey.data(),
      uncompressed_pubkey.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE,
        "wally_ec_public_key_decompress error. ret={} compressed pubkey={}.",
        ret, ByteData(pubkey).GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Decompressed Pubkey error.");
  }
  return Pubkey(uncompressed_pubkey);
}

Privkey Privkey::GenerageRandomKey() {
  std::vector<uint8_t> privkey;
  int ret = WALLY_OK;

  do {
    privkey = RandomNumberUtil::GetRandomBytes(kPrivkeySize);
    ret = wally_ec_private_key_verify(privkey.data(), privkey.size());
  } while (ret != WALLY_OK);

  return Privkey(ByteData(privkey));
}

Privkey Privkey::CreateTweakAdd(const ByteData256 &tweak) const {
  ByteData tweak_added = WallyUtil::AddTweakPrivkey(data_, tweak);
  return Privkey(tweak_added);
}

Privkey Privkey::CreateTweakAdd(const Privkey &tweak) const {
  ByteData tweak_added =
      WallyUtil::AddTweakPrivkey(data_, ByteData256(tweak.data_));
  return Privkey(tweak_added);
}

Privkey Privkey::CreateTweakMul(const ByteData256 &tweak) const {
  ByteData tweak_muled = WallyUtil::MulTweakPrivkey(data_, tweak);
  return Privkey(tweak_muled);
}

Privkey Privkey::CreateTweakMul(const Privkey &tweak) const {
  ByteData tweak_muled =
      WallyUtil::MulTweakPrivkey(data_, ByteData256(tweak.data_));
  return Privkey(tweak_muled);
}

Privkey Privkey::CreateNegate() const {
  ByteData negated = WallyUtil::NegatePrivkey(data_);
  return Privkey(negated);
}

bool Privkey::IsInvalid() const { return !IsValid(); }

bool Privkey::IsValid() const { return IsValid(data_.GetBytes()); }

bool Privkey::Equals(const Privkey &privkey) const {
  return data_.Equals(privkey.data_);
}

bool Privkey::IsValid(const std::vector<uint8_t> &buffer) {
  if (buffer.size() > 0) {
    int ret = wally_ec_private_key_verify(buffer.data(), buffer.size());
    return ret == WALLY_OK;
  }
  return false;
}

ByteData Privkey::CalculateEcSignature(
    const ByteData256 &signature_hash, bool has_grind_r) const {
  return SignatureUtil::CalculateEcSignature(
      signature_hash, *this, has_grind_r);
}

void Privkey::SetPubkeyCompressed(bool is_compressed) {
  is_compressed_ = is_compressed;
}

void Privkey::SetNetType(NetType net_type) { net_type_ = net_type; }

Privkey Privkey::operator+=(const Privkey &right) {
  Privkey key = CreateTweakAdd(right);
  *this = key;
  return *this;
}

Privkey Privkey::operator+=(const ByteData256 &right) {
  Privkey key = CreateTweakAdd(right);
  *this = key;
  return *this;
}

Privkey Privkey::operator-=(const Privkey &right) {
  Privkey key = CreateTweakAdd(right.CreateNegate());
  *this = key;
  return *this;
}

Privkey Privkey::operator-=(const ByteData256 &right) {
  Privkey sk(right);
  Privkey key = CreateTweakAdd(sk.CreateNegate());
  *this = key;
  return *this;
}

Privkey Privkey::operator*=(const Privkey &right) {
  Privkey key = CreateTweakMul(right);
  *this = key;
  return *this;
}

Privkey Privkey::operator*=(const ByteData256 &right) {
  Privkey key = CreateTweakMul(right);
  *this = key;
  return *this;
}

// global operator overloading
Privkey operator+(const Privkey &left, const Privkey &right) {
  return left.CreateTweakAdd(right);
}

Privkey operator+(const Privkey &left, const ByteData256 &right) {
  return left.CreateTweakAdd(right);
}

Privkey operator-(const Privkey &left, const Privkey &right) {
  Privkey key = left;
  key -= right;
  return key;
}

Privkey operator-(const Privkey &left, const ByteData256 &right) {
  Privkey key = left;
  key -= right;
  return key;
}

Privkey operator*(const Privkey &left, const Privkey &right) {
  return left.CreateTweakMul(right);
}

Privkey operator*(const Privkey &left, const ByteData256 &right) {
  return left.CreateTweakMul(right);
}

}  // namespace core
}  // namespace cfd
