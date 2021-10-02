// Copyright 2020 CryptoGarage
/**
 * @file cfdcore_hdwallet.cpp
 *
 * @brief implementation of BIP32/BIP39/BIP44 classes
 */

#include "cfdcore/cfdcore_hdwallet.h"

#include <algorithm>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT
#ifndef CFD_DISABLE_ELEMENTS
#include "cfdcore/cfdcore_elements_address.h"
#endif  // CFD_DISABLE_ELEMENTS

namespace cfd {
namespace core {

using logger::warn;

// ----------------------------------------------------------------------------
// Definitions in the file
// ----------------------------------------------------------------------------
/// empty seed string (64byte)
static constexpr const char* kEmptySeedStr =
    "00000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000";  // NOLINT

/**
 * @brief Get an array from a string path.
 * @param[in] string_path       child number string path
 * @param[in] caller_name       caller class name
 * @param[in] depth             current key depth
 * @return uint32_t array
 */
static std::vector<uint32_t> ToArrayFromString(
    const std::string& string_path, const std::string& caller_name,
    uint8_t depth) {
  std::vector<uint32_t> result;
  std::vector<std::string> list = StringUtil::Split(string_path, "/");
  for (size_t index = 0; index < list.size(); ++index) {
    std::string str = list[index];
    bool hardened = false;
    if (str.size() <= 1) {
      // do nothing
    } else if (
        (str.back() == '\'') || (str.back() == 'h') || (str.back() == 'H')) {
      str = str.substr(0, str.size() - 1);
      hardened = true;
    }
    if ((str == "m") || (str == "M")) {
      if (depth != 0) {
        warn(
            CFD_LOG_SOURCE, "{} bip32 path fail. this key is not master key.",
            caller_name);
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            caller_name + " bip32 path fail. this key is not master key.");
      }
      continue;  // master key
    }
    if (str.empty()) {
      if (index == 0) {
        // start slash pattern
        continue;
      } else {
        warn(
            CFD_LOG_SOURCE, "{} bip32 string path fail. empty item.",
            caller_name);
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            caller_name + " bip32 string path fail. empty item.");
      }
    }

    // Conversion by strtol function
    char* p_str_end = nullptr;
    uint32_t value;
    if ((str.size() > 2) && (str[0] == '0') && (str[1] == 'x')) {
      value = std::strtoul(str.c_str(), &p_str_end, 16);
    } else {
      value = std::strtoul(str.c_str(), &p_str_end, 10);
    }
    if (str.empty() || ((p_str_end != nullptr) && (*p_str_end != '\0'))) {
      warn(CFD_LOG_SOURCE, "{} bip32 string path fail.", caller_name);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          caller_name + " bip32 string path fail.");
    }
    if (hardened) value |= 0x80000000;
    result.push_back(static_cast<uint32_t>(value));
  }

  if (result.empty()) {
    warn(CFD_LOG_SOURCE, "{} bip32 string path empty.", caller_name);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        caller_name + " bip32 string path empty.");
  }

  return result;
}

// ----------------------------------------------------------------------------
// HDWallet
// ----------------------------------------------------------------------------
HDWallet::HDWallet() : seed_(ByteData(kEmptySeedStr)) {
  // do nothing
}

HDWallet::HDWallet(const ByteData& seed) : seed_(seed) {
  if ((seed.GetDataSize() != HDWallet::kSeed128Size) &&
      (seed.GetDataSize() != HDWallet::kSeed256Size) &&
      (seed.GetDataSize() != HDWallet::kSeed512Size)) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Seed length error.");
  }
}

HDWallet::HDWallet(
    std::vector<std::string> mnemonic, std::string passphrase,
    bool use_ideographic_space)
    : seed_(ByteData(kEmptySeedStr)) {
  seed_ = ConvertMnemonicToSeed(mnemonic, passphrase, use_ideographic_space);
  if ((seed_.GetDataSize() != HDWallet::kSeed128Size) &&
      (seed_.GetDataSize() != HDWallet::kSeed256Size) &&
      (seed_.GetDataSize() != HDWallet::kSeed512Size)) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Seed length error.");
  }
}

ByteData HDWallet::GetSeed() const { return seed_; }

ExtPrivkey HDWallet::GeneratePrivkey(
    NetType network_type, Bip32FormatType format_type) const {
  return ExtPrivkey(seed_, network_type, format_type);
}

ExtPrivkey HDWallet::GeneratePrivkey(
    NetType network_type, uint32_t child_num,
    Bip32FormatType format_type) const {
  std::vector<uint32_t> path = {child_num};
  return GeneratePrivkey(network_type, path, format_type);
}

ExtPrivkey HDWallet::GeneratePrivkey(
    NetType network_type, const std::vector<uint32_t>& path,
    Bip32FormatType format_type) const {
  ExtPrivkey privkey(seed_, network_type, format_type);
  return privkey.DerivePrivkey(path);
}

ExtPrivkey HDWallet::GeneratePrivkey(
    NetType network_type, const std::string& string_path,
    Bip32FormatType format_type) const {
  ExtPrivkey privkey(seed_, network_type, format_type);
  return privkey.DerivePrivkey(string_path);
}

KeyData HDWallet::GeneratePrivkeyData(
    NetType network_type, const std::vector<uint32_t>& path,
    Bip32FormatType format_type) const {
  ExtPrivkey privkey(seed_, network_type, format_type);
  ExtPrivkey key = privkey.DerivePrivkey(path);
  auto fingerprint = privkey.GetPrivkey().GeneratePubkey().GetFingerprint();
  return KeyData(key, path, fingerprint);
}

KeyData HDWallet::GeneratePrivkeyData(
    NetType network_type, const std::string& string_path,
    Bip32FormatType format_type) const {
  ExtPrivkey privkey(seed_, network_type, format_type);
  ExtPrivkey key = privkey.DerivePrivkey(string_path);
  auto fingerprint = privkey.GetPrivkey().GeneratePubkey().GetFingerprint();
  return KeyData(key, string_path, fingerprint);
}

ExtPubkey HDWallet::GeneratePubkey(
    NetType network_type, Bip32FormatType format_type) const {
  ExtPrivkey privkey(seed_, network_type, format_type);
  return privkey.GetExtPubkey();
}

ExtPubkey HDWallet::GeneratePubkey(
    NetType network_type, uint32_t child_num,
    Bip32FormatType format_type) const {
  std::vector<uint32_t> path = {child_num};
  return GeneratePubkey(network_type, path, format_type);
}

ExtPubkey HDWallet::GeneratePubkey(
    NetType network_type, const std::vector<uint32_t>& path,
    Bip32FormatType format_type) const {
  ExtPrivkey privkey(seed_, network_type, format_type);
  return privkey.DerivePubkey(path);
}

ExtPubkey HDWallet::GeneratePubkey(
    NetType network_type, const std::string& string_path,
    Bip32FormatType format_type) const {
  ExtPrivkey privkey(seed_, network_type, format_type);
  return privkey.DerivePubkey(string_path);
}

KeyData HDWallet::GeneratePubkeyData(
    NetType network_type, const std::vector<uint32_t>& path,
    Bip32FormatType format_type) const {
  ExtPrivkey privkey(seed_, network_type, format_type);
  ExtPrivkey key = privkey.DerivePrivkey(path);
  auto fingerprint = privkey.GetPrivkey().GeneratePubkey().GetFingerprint();
  return KeyData(key.GetExtPubkey(), path, fingerprint);
}

KeyData HDWallet::GeneratePubkeyData(
    NetType network_type, const std::string& string_path,
    Bip32FormatType format_type) const {
  ExtPrivkey privkey(seed_, network_type, format_type);
  ExtPrivkey key = privkey.DerivePrivkey(string_path);
  auto fingerprint = privkey.GetPrivkey().GeneratePubkey().GetFingerprint();
  return KeyData(key.GetExtPubkey(), string_path, fingerprint);
}

std::vector<std::string> HDWallet::GetMnemonicWordlist(
    const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::GetMnemonicWordlist(language);
}

std::vector<std::string> HDWallet::ConvertEntropyToMnemonic(
    const ByteData& entropy, const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::ConvertEntropyToMnemonic(entropy, language);
}

ByteData HDWallet::ConvertMnemonicToEntropy(
    const std::vector<std::string>& mnemonic, const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::ConvertMnemonicToEntropy(mnemonic, language);
}

bool HDWallet::CheckValidMnemonic(
    const std::vector<std::string>& mnemonic, const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::CheckValidMnemonic(mnemonic, language);
}

bool HDWallet::CheckSupportedLanguages(const std::string& language) {
  std::vector<std::string> slangs = WallyUtil::GetSupportedMnemonicLanguages();
  return (
      std::find(slangs.cbegin(), slangs.cend(), language) != slangs.cend());
}

ByteData HDWallet::ConvertMnemonicToSeed(
    const std::vector<std::string>& mnemonic, const std::string& passphrase,
    bool use_ideographic_space) {
  return WallyUtil::ConvertMnemonicToSeed(
      mnemonic, passphrase, use_ideographic_space);
}

// ----------------------------------------------------------------------------
// Extkey
// ----------------------------------------------------------------------------
//! empty fingerprint
static const ByteData kEmptyFingerprint = ByteData("00000000");

/**
 * @brief Get the key format data from extkey version.
 * @param[in] version   extkey version
 * @return key format data.
 */
static KeyFormatData GetKeyFormatFromVersion(uint32_t version) {
  for (const auto& format_data : GetKeyFormatList()) {
    if (format_data.IsFindVersion(version)) {
      return format_data;
    }
  }
  throw CfdException(
      CfdError::kCfdIllegalArgumentError, "unsupported extkey version.");
}

/**
 * @brief Get the extkey version pair.
 * @param[in] version   extkey version
 * @return extkey version pair data.
 */
static ExtkeyVersionPair GetExtkeyVersionPair(uint32_t version) {
  return GetKeyFormatFromVersion(version).GetVersionPair(version);
}

/**
 * @brief Get the network type from extkey version.
 * @param[in] version   extkey version
 * @return network type.
 */
static NetType GetNetworkTypeFromVersion(uint32_t version) {
  return GetKeyFormatFromVersion(version).GetNetType();
}

/**
 * @brief convert to extkey version.
 * @param[in] network_type   extkey version
 * @param[in] format_type   extkey version
 * @param[in] is_privkey   extkey version
 * @return extkey version
 */
static uint32_t ConvertToExtkeyVersion(
    NetType network_type, Bip32FormatType format_type, bool is_privkey) {
  auto format_data = GetKeyFormatData(network_type);
  auto versions = format_data.GetVersionPair(format_type);
  return (is_privkey) ? versions.privkey_version : versions.pubkey_version;
}

/**
 * @brief Get related pubkey address list.
 * @param[in] extkey              extended key
 * @param[in] address_type        address type
 * @param[in] network_parameters  network parameter. (nullptr is bitcoin)
 * @param[in] net_type            network type (auto is kCustomChain)
 * @return address list.
 */
static std::vector<Address> GetPubkeyAddressesInternal(
    const Extkey& extkey, AddressType address_type,
    const std::vector<AddressFormatData>* network_parameters,
    NetType net_type) {
  std::vector<Address> result;
  auto base_nettype = extkey.GetNetworkType();
  NetType network =
      (net_type == NetType::kCustomChain) ? base_nettype : net_type;
  std::vector<AddressFormatData> net_params;
  if (network_parameters != nullptr) {
    net_params = *network_parameters;
  } else if (
      (net_type == NetType::kCustomChain) || (net_type <= NetType::kRegtest)) {
    net_params = GetBitcoinAddressFormatList();
  } else {
#ifndef CFD_DISABLE_ELEMENTS
    net_params = GetElementsAddressFormatList();
#else
    net_params = GetBitcoinAddressFormatList();
#endif  // CFD_DISABLE_ELEMENTS
  }

  bool is_mainnet_base = (base_nettype == NetType::kMainnet);
  bool is_mainnet =
      ((network == NetType::kMainnet) || (network == NetType::kLiquidV1));
  if (is_mainnet != is_mainnet_base) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Unmatch network type. Please match extkey network type.");
  }

  Bip32FormatType type = extkey.GetFormatType();
  std::vector<AddressType> targets;
  if ((address_type == AddressType::kP2pkhAddress) ||
      (address_type == AddressType::kP2shP2wpkhAddress) ||
      (address_type == AddressType::kP2wpkhAddress) ||
      (address_type == AddressType::kTaprootAddress)) {
    if (((type == Bip32FormatType::kBip49) &&
         (address_type != AddressType::kP2shP2wpkhAddress)) ||
        ((type == Bip32FormatType::kBip84) &&
         (address_type != AddressType::kP2wpkhAddress))) {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Invalid address type. target extkey is fixed address type.");
    }
    targets.push_back(address_type);
  } else if (address_type != AddressType::kWitnessUnknown) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid address type.");
  } else if (type == Bip32FormatType::kBip49) {  // auto type
    targets.push_back(AddressType::kP2shP2wpkhAddress);
  } else if (type == Bip32FormatType::kBip84) {  // auto type
    targets.push_back(AddressType::kP2wpkhAddress);
  } else {  // auto type
    // TODO(k-matsuzawa): If bip32format is normal, set the beginning to p2wpkh
    targets.push_back(AddressType::kP2wpkhAddress);
    targets.push_back(AddressType::kTaprootAddress);
    targets.push_back(AddressType::kP2shP2wpkhAddress);
    targets.push_back(AddressType::kP2pkhAddress);
  }

  for (const auto& addr_type : targets) {
    if (addr_type == AddressType::kP2shP2wpkhAddress) {
      auto script = ScriptUtil::CreateP2wpkhLockingScript(extkey.GetPubkey());
      result.emplace_back(Address(network, script, net_params));
    } else if (addr_type == AddressType::kP2wpkhAddress) {
      result.emplace_back(Address(
          network, WitnessVersion::kVersion0, extkey.GetPubkey(), net_params));
    } else if (addr_type == AddressType::kTaprootAddress) {
      result.emplace_back(Address(
          network, WitnessVersion::kVersion1,
          SchnorrPubkey::FromPubkey(extkey.GetPubkey()), net_params));
    } else {
      result.emplace_back(Address(network, extkey.GetPubkey(), net_params));
    }
  }
  return result;
}

Extkey::Extkey() {
  // do nothing
}

Extkey::Extkey(
    const ByteData& seed, NetType network_type, Bip32FormatType format_type)
    : Extkey(seed, ConvertToExtkeyVersion(network_type, format_type, true)) {
  // convert to version
}

Extkey::Extkey(const ByteData& seed, uint32_t version) {
  static const std::string kBip32Seed = "Bitcoin seed";
  auto versions = GetExtkeyVersionPair(version);
  if (versions.privkey_version != version) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey invalid version.");
  }
  switch (seed.GetDataSize()) {
    case HDWallet::kSeed128Size:
    case HDWallet::kSeed256Size:
    case HDWallet::kSeed512Size:
      break;
    default:
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "ExtPrivkey Seed length error.");
  }

  std::vector<uint8_t> extkey_seed(strlen(kBip32Seed.c_str()) + 1);
  memcpy(extkey_seed.data(), kBip32Seed.c_str(), extkey_seed.size());
  auto hash = CryptoUtil::HmacSha512(extkey_seed, seed);

  version_ = version;
  NetType net_type = GetNetworkTypeFromVersion(version);
  auto hash_datas = hash.SplitData(std::vector<uint32_t>{32, 32});
  privkey_ = Privkey(hash_datas[0], net_type);
  pubkey_ = privkey_.GetPubkey();
  chaincode_ = ByteData256(hash_datas[1]);
  if (chaincode_.IsEmpty()) {
    throw CfdException(
        CfdError::kCfdIllegalStateError,
        "Invalid chaincode. please change seed.");
  }
  depth_ = 0;
  child_num_ = 0;
  fingerprint_ = kEmptyFingerprint;
}

Extkey::Extkey(const ByteData& serialize_data, const ByteData256& tweak_sum)
    : tweak_sum_(tweak_sum) {
  if (serialize_data.GetDataSize() != Extkey::kSerializeSize) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid serialize extkey size.");
  }

  Deserializer dec(serialize_data);
  version_ = dec.ReadUint32FromBigEndian();
  auto format_data = GetKeyFormatFromVersion(version_);
  NetType nettype = format_data.GetNetType();

  depth_ = dec.ReadUint8();
  fingerprint_ = dec.ReadBuffer(4);
  child_num_ = dec.ReadUint32FromBigEndian();
  chaincode_ = ByteData256(dec.ReadBuffer(kByteData256Length));
  if (chaincode_.IsEmpty()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid chaincode.");
  }
  auto buf = dec.ReadBuffer(Pubkey::kCompressedPubkeySize);
  if (buf[0] == 0) {
    privkey_ = Privkey(ByteData(&buf[1], kByteData256Length), nettype);
    pubkey_ = privkey_.GetPubkey();
  } else if (Pubkey::IsValid(buf)) {
    pubkey_ = Pubkey(ByteData(buf));
  } else {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid pubkey state.");
  }

  auto versions = format_data.GetVersionPair(version_);
  if (((versions.privkey_version == version_) && (!privkey_.IsValid())) ||
      ((versions.pubkey_version == version_) && privkey_.IsValid())) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid key state.");
  }
  if ((depth_ == 0) && (!fingerprint_.Equals(kEmptyFingerprint))) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid depth state.");
  }
}

Extkey::Extkey(const std::string& base58_data)
    : Extkey(CryptoUtil::DecodeBase58Check(base58_data), ByteData256()) {}

Extkey::Extkey(const std::string& base58_data, const ByteData256& tweak_sum)
    : Extkey(CryptoUtil::DecodeBase58Check(base58_data), tweak_sum) {}

ByteData Extkey::GetData() const {
  if (!IsValid()) return ByteData();

  Serializer serial(kSerializeSize);
  serial.AddDirectBigEndianNumber(version_);
  serial.AddDirectByte(depth_);
  serial.AddDirectBytes(fingerprint_);
  serial.AddDirectBigEndianNumber(child_num_);
  serial.AddDirectBytes(chaincode_);
  if (privkey_.IsValid()) {
    serial.AddDirectByte(0);
    serial.AddDirectBytes(privkey_.GetData());
  } else {
    serial.AddDirectBytes(pubkey_.GetData());
  }
  return serial.Output();
}

std::string Extkey::ToString() const {
  return CryptoUtil::EncodeBase58Check(GetData());
}

Extkey Extkey::FromPrivkey(
    uint32_t version, const ByteData& parent_fingerprint,
    const Privkey& privkey, const ByteData256& chain_code, uint8_t depth,
    uint32_t child_num, ByteData256 tweak_sum) {
  if (!privkey.IsValid()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to privkey. ExtPrivkey invalid privkey.");
  }
  auto versions = GetExtkeyVersionPair(version);
  if (versions.privkey_version != version) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey invalid version.");
  }
  if (chain_code.IsEmpty()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to chaincode. chaincode need the not all-zero.");
  }
  if (parent_fingerprint.GetDataSize() < 4) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to parent_fingerprint. fingerprint must be at least 4 bytes.");
  }
  Extkey result;
  result.privkey_ = privkey;
  result.privkey_.SetNetType(GetNetworkTypeFromVersion(version));
  result.privkey_.SetPubkeyCompressed(true);
  result.pubkey_ = result.privkey_.GetPubkey();
  result.version_ = version;
  result.chaincode_ = chain_code;
  result.depth_ = depth;
  result.child_num_ = child_num;
  result.tweak_sum_ = tweak_sum;
  result.fingerprint_ = parent_fingerprint.SplitData(4);
  if ((depth == 0) && (!result.fingerprint_.Equals(kEmptyFingerprint))) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid depth state.");
  }
  return result;
}

Extkey Extkey::FromPubkey(
    uint32_t version, const ByteData& parent_fingerprint, const Pubkey& pubkey,
    const ByteData256& chain_code, uint8_t depth, uint32_t child_num,
    ByteData256 tweak_sum) {
  if (!pubkey.IsValid()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to pubkey. ExtPubkey invalid pubkey.");
  }
  auto versions = GetExtkeyVersionPair(version);
  if (versions.pubkey_version != version) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPubkey invalid version.");
  }
  if (chain_code.IsEmpty()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to chaincode. chaincode need the not all-zero.");
  }
  if (parent_fingerprint.GetDataSize() < 4) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to parent_fingerprint. fingerprint must be at least 4 bytes.");
  }

  Pubkey key = pubkey;
  if (!key.IsCompress()) key = key.Compress();
  Extkey result;
  result.pubkey_ = key;
  result.version_ = version;
  result.chaincode_ = chain_code;
  result.depth_ = depth;
  result.child_num_ = child_num;
  result.tweak_sum_ = tweak_sum;

  result.fingerprint_ = parent_fingerprint.SplitData(4);
  if ((depth == 0) && (!result.fingerprint_.Equals(kEmptyFingerprint))) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid depth state.");
  }
  return result;
}

Extkey Extkey::Derive(uint32_t child_num) const {
  const bool has_private = privkey_.IsValid();
  Serializer buf;

  NetType nettype = GetNetworkTypeFromVersion(version_);
  if (depth_ == 0xff) {
    throw CfdException(CfdError::kCfdIllegalStateError, "depth is maximum.");
  }

  if (child_num >= kHardenedKey) {
    if (!has_private) {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "hardened child_num can use privkey only.");
    }
    buf.AddDirectByte(0);
    buf.AddDirectBytes(privkey_.GetData());
  } else {
    buf.AddDirectBytes(pubkey_.GetData());
  }
  buf.AddDirectBigEndianNumber(child_num);

  auto hash = CryptoUtil::HmacSha512(chaincode_.GetBytes(), buf.Output());
  auto hash_datas = hash.SplitData(std::vector<uint32_t>{32, 32});
  ByteData256 tweak(hash_datas[0]);

  Extkey result;
  result.chaincode_ = ByteData256(hash_datas[1]);
  if (has_private) {
    result.privkey_ = privkey_.CreateTweakAdd(tweak);
    result.privkey_.SetNetType(nettype);
    result.pubkey_ = result.privkey_.GetPubkey();
  } else {
    result.pubkey_ = pubkey_.CreateTweakAdd(tweak);
    if (tweak_sum_.IsEmpty()) {
      result.tweak_sum_ = tweak;
    } else {
      Privkey sk(tweak_sum_);
      result.tweak_sum_ = ByteData256(sk.CreateTweakAdd(tweak).GetData());
    }
  }

  result.version_ = version_;
  result.depth_ = depth_ + 1;
  result.child_num_ = child_num;
  result.fingerprint_ = pubkey_.GetFingerprint();
  return result;
}

Extkey Extkey::Derive(const std::vector<uint32_t>& path) const {
  Extkey key = *this;
  for (const auto& child_num : path) key = key.Derive(child_num);
  return key;
}

Extkey Extkey::Derive(const std::string& string_path) const {
  std::vector<uint32_t> path =
      ToArrayFromString(string_path, "Extkey", depth_);
  return Derive(path);
}

Extkey Extkey::ToPubkey() const {
  if (!privkey_.IsValid()) {
    throw CfdException(
        CfdError::kCfdIllegalStateError,
        "This key is pubkey only. please use extprivkey.");
  }
  auto ver_pair = GetExtkeyVersionPair(version_);

  Extkey result;
  result.version_ = ver_pair.pubkey_version;
  result.depth_ = depth_;
  result.child_num_ = child_num_;
  result.pubkey_ = pubkey_;
  result.fingerprint_ = fingerprint_;
  result.chaincode_ = chaincode_;
  return result;
}

Address Extkey::GetPubkeyAddress(
    AddressType address_type,
    const std::vector<AddressFormatData>* network_parameters,
    NetType net_type) {
  auto addresses = GetPubkeyAddressesInternal(
      *this, address_type, network_parameters, net_type);
  if (addresses.empty()) {
    throw CfdException(CfdError::kCfdInternalError, "address list is empty.");
  }
  return addresses[0];
}

std::vector<Address> Extkey::GetPubkeyAddresses(
    const std::vector<AddressFormatData>* network_parameters,
    NetType net_type) {
  return GetPubkeyAddressesInternal(
      *this, AddressType::kWitnessUnknown, network_parameters, net_type);
}

bool Extkey::IsValid() const { return pubkey_.IsValid(); }

bool Extkey::HasPrivkey() const { return privkey_.IsValid(); }

ByteData256 Extkey::GetPubTweakSum() const { return tweak_sum_; }

ByteData256 Extkey::GetChainCode() const { return chaincode_; }

uint32_t Extkey::GetVersion() const { return version_; }

uint8_t Extkey::GetDepth() const { return depth_; }

uint32_t Extkey::GetChildNum() const { return child_num_; }

ByteData Extkey::GetVersionData() const {
  Serializer buf(4);
  buf.AddDirectBigEndianNumber(version_);
  return buf.Output();
}

uint32_t Extkey::GetFingerprint() const {
  Deserializer dec(fingerprint_);
  return dec.ReadUint32FromBigEndian();
}

ByteData Extkey::GetFingerprintData() const {
  if (fingerprint_.IsEmpty()) return kEmptyFingerprint;
  return fingerprint_;
}

Pubkey Extkey::GetPubkey() const { return pubkey_; }

Privkey Extkey::GetPrivkey() const { return privkey_; }

NetType Extkey::GetNetworkType() const {
  return GetNetworkTypeFromVersion(version_);
}

Bip32FormatType Extkey::GetFormatType() const {
  return GetKeyFormatFromVersion(version_).GetVersionFormatType(version_);
}

// ----------------------------------------------------------------------------
// ExtPrivkey
// ----------------------------------------------------------------------------
ExtPrivkey::ExtPrivkey() {
  // do nothing
}

ExtPrivkey::ExtPrivkey(
    const ByteData& seed, NetType network_type, Bip32FormatType format_type)
    : Extkey(seed, network_type, format_type) {
  // do nothing
}

ExtPrivkey::ExtPrivkey(const ByteData& serialize_data)
    : ExtPrivkey(serialize_data, ByteData256()) {
  // do nothing
}

ExtPrivkey::ExtPrivkey(
    const ByteData& serialize_data, const ByteData256& tweak_sum)
    : Extkey(serialize_data, tweak_sum) {
  if (!privkey_.IsValid()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Invalid serialize data. this data is ExtPubkey data.");
  }
}

ExtPrivkey::ExtPrivkey(const std::string& base58_data)
    : ExtPrivkey(base58_data, ByteData256()) {
  // do nothing
}

ExtPrivkey::ExtPrivkey(
    const std::string& base58_data, const ByteData256& tweak_sum)
    : Extkey(base58_data, tweak_sum) {
  if (!privkey_.IsValid()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Invalid serialize data. this data is ExtPubkey data.");
  }
}

ExtPrivkey::ExtPrivkey(
    NetType network_type, const Privkey& parent_key,
    const ByteData256& parent_chain_code, uint8_t parent_depth,
    uint32_t child_num, Bip32FormatType format_type)
    : Extkey(Extkey::FromPrivkey(
                 ConvertToExtkeyVersion(network_type, format_type, true),
                 kEmptyFingerprint, parent_key, parent_chain_code,
                 parent_depth, 0)
                 .Derive(child_num)) {
  // do nothing
}

ExtPrivkey::ExtPrivkey(
    NetType network_type, const Privkey& parent_key, const Privkey& privkey,
    const ByteData256& chain_code, uint8_t depth, uint32_t child_num,
    Bip32FormatType format_type)
    : ExtPrivkey(
          network_type, parent_key.GeneratePubkey().GetFingerprint(), privkey,
          chain_code, depth, child_num, format_type) {
  if (!parent_key.IsValid()) {
    warn(CFD_LOG_SOURCE, "invalid privkey.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to privkey. ExtPrivkey invalid privkey.");
  }
}

ExtPrivkey::ExtPrivkey(
    NetType network_type, const ByteData& parent_fingerprint,
    const Privkey& privkey, const ByteData256& chain_code, uint8_t depth,
    uint32_t child_num, Bip32FormatType format_type)
    : Extkey(Extkey::FromPrivkey(
          ConvertToExtkeyVersion(network_type, format_type, true),
          parent_fingerprint, privkey, chain_code, depth, child_num)) {
  if (!privkey.IsValid()) {
    warn(CFD_LOG_SOURCE, "invalid privkey.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to privkey. ExtPrivkey invalid privkey.");
  }
}

ExtPrivkey::ExtPrivkey(const Extkey& key_data) {
  version_ = key_data.GetVersion();
  depth_ = key_data.GetDepth();
  child_num_ = key_data.GetChildNum();
  pubkey_ = key_data.GetPubkey();
  privkey_ = key_data.GetPrivkey();
  fingerprint_ = key_data.GetFingerprintData();
  chaincode_ = key_data.GetChainCode();
}

ExtPrivkey ExtPrivkey::DerivePrivkey(uint32_t child_num) const {
  std::vector<uint32_t> path = {child_num};
  return DerivePrivkey(path);
}

ExtPrivkey ExtPrivkey::DerivePrivkey(const std::vector<uint32_t>& path) const {
  return ExtPrivkey(Derive(path));
}

ExtPrivkey ExtPrivkey::DerivePrivkey(const std::string& string_path) const {
  std::vector<uint32_t> path =
      ToArrayFromString(string_path, "ExtPrivkey", depth_);
  return DerivePrivkey(path);
}

KeyData ExtPrivkey::DerivePrivkeyData(
    const std::vector<uint32_t>& path) const {
  ExtPrivkey key = DerivePrivkey(path);
  auto fingerprint = privkey_.GeneratePubkey().GetFingerprint();
  return KeyData(key, path, fingerprint);
}

KeyData ExtPrivkey::DerivePrivkeyData(const std::string& string_path) const {
  ExtPrivkey key = DerivePrivkey(string_path);
  auto fingerprint = privkey_.GeneratePubkey().GetFingerprint();
  return KeyData(key, string_path, fingerprint);
}

ExtPubkey ExtPrivkey::GetExtPubkey() const { return ExtPubkey(ToPubkey()); }

ExtPubkey ExtPrivkey::DerivePubkey(uint32_t child_num) const {
  std::vector<uint32_t> path = {child_num};
  return DerivePubkey(path);
}

ExtPubkey ExtPrivkey::DerivePubkey(const std::vector<uint32_t>& path) const {
  ExtPrivkey privkey = DerivePrivkey(path);
  return privkey.GetExtPubkey();
}

ExtPubkey ExtPrivkey::DerivePubkey(const std::string& string_path) const {
  ExtPrivkey privkey = DerivePrivkey(string_path);
  return privkey.GetExtPubkey();
}

KeyData ExtPrivkey::DerivePubkeyData(const std::vector<uint32_t>& path) const {
  ExtPubkey key = DerivePubkey(path);
  auto fingerprint = privkey_.GeneratePubkey().GetFingerprint();
  return KeyData(key, path, fingerprint);
}

KeyData ExtPrivkey::DerivePubkeyData(const std::string& string_path) const {
  ExtPubkey key = DerivePubkey(string_path);
  auto fingerprint = privkey_.GeneratePubkey().GetFingerprint();
  return KeyData(key, string_path, fingerprint);
}

bool ExtPrivkey::IsValid() const { return privkey_.IsValid(); }

// ----------------------------------------------------------------------------
// ExtPubkey
// ----------------------------------------------------------------------------
ExtPubkey::ExtPubkey() {
  // do nothing
}

ExtPubkey::ExtPubkey(const ByteData& serialize_data)
    : ExtPubkey(serialize_data, ByteData256()) {
  // do nothing
}

ExtPubkey::ExtPubkey(
    const ByteData& serialize_data, const ByteData256& tweak_sum)
    : Extkey(serialize_data, tweak_sum) {
  if (privkey_.IsValid()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Invalid serialize data. this data is ExtPrivkey data.");
  }
}

ExtPubkey::ExtPubkey(const std::string& base58_data)
    : ExtPubkey(base58_data, ByteData256()) {
  // do nothing
}

ExtPubkey::ExtPubkey(
    const std::string& base58_data, const ByteData256& tweak_sum)
    : Extkey(base58_data, tweak_sum) {
  if (privkey_.IsValid()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Invalid serialize data. this data is ExtPrivkey data.");
  }
}

ExtPubkey::ExtPubkey(
    NetType network_type, const Pubkey& parent_key,
    const ByteData256& parent_chain_code, uint8_t parent_depth,
    uint32_t child_num, Bip32FormatType format_type)
    : Extkey(Extkey::FromPubkey(
                 ConvertToExtkeyVersion(network_type, format_type, false),
                 kEmptyFingerprint, parent_key, parent_chain_code,
                 parent_depth, 0)
                 .Derive(child_num)) {
  // do nothing
}

ExtPubkey::ExtPubkey(
    NetType network_type, const Pubkey& parent_key, const Pubkey& pubkey,
    const ByteData256& chain_code, uint8_t depth, uint32_t child_num,
    Bip32FormatType format_type)
    : ExtPubkey(
          network_type, parent_key.GetFingerprint(), pubkey, chain_code, depth,
          child_num, format_type) {
  if (!parent_key.IsValid()) {
    warn(CFD_LOG_SOURCE, "invalid pubkey.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to pubkey. ExtPubkey invalid pubkey.");
  }
}

ExtPubkey::ExtPubkey(
    NetType network_type, const ByteData& parent_fingerprint,
    const Pubkey& pubkey, const ByteData256& chain_code, uint8_t depth,
    uint32_t child_num, Bip32FormatType format_type)
    : Extkey(Extkey::FromPubkey(
          ConvertToExtkeyVersion(network_type, format_type, false),
          parent_fingerprint, pubkey, chain_code, depth, child_num)) {}

ExtPubkey::ExtPubkey(const Extkey& key_data) {
  version_ = key_data.GetVersion();
  depth_ = key_data.GetDepth();
  child_num_ = key_data.GetChildNum();
  pubkey_ = key_data.GetPubkey();
  fingerprint_ = key_data.GetFingerprintData();
  chaincode_ = key_data.GetChainCode();
  tweak_sum_ = key_data.GetPubTweakSum();
}

ExtPubkey ExtPubkey::DerivePubkey(uint32_t child_num) const {
  std::vector<uint32_t> path = {child_num};
  return DerivePubkey(path);
}

ExtPubkey ExtPubkey::DerivePubkey(const std::vector<uint32_t>& path) const {
  return ExtPubkey(Derive(path));
}

ExtPubkey ExtPubkey::DerivePubkey(const std::string& string_path) const {
  return ExtPubkey(Derive(string_path));
}

KeyData ExtPubkey::DerivePubkeyData(const std::vector<uint32_t>& path) const {
  ExtPubkey key(Derive(path));
  auto fingerprint = pubkey_.GetFingerprint();
  return KeyData(key, path, fingerprint);
}

KeyData ExtPubkey::DerivePubkeyData(const std::string& string_path) const {
  ExtPubkey key(Derive(string_path));
  auto fingerprint = pubkey_.GetFingerprint();
  return KeyData(key, string_path, fingerprint);
}

ByteData256 ExtPubkey::DerivePubTweak(
    const std::vector<uint32_t>& path) const {
  ExtPubkey key(Derive(path));
  return key.GetPubTweakSum();
}

// ----------------------------------------------------------------------------
// KeyData
// ----------------------------------------------------------------------------

KeyData::KeyData() {
  // do nothing
}

KeyData::KeyData(
    const ExtPrivkey& ext_privkey, const std::string& child_path,
    const ByteData& finterprint)
    : extprivkey_(ext_privkey), fingerprint_(finterprint) {
  if (!child_path.empty()) {
    path_ = ToArrayFromString(child_path, "KeyData", 0);
  }
  extpubkey_ = ext_privkey.GetExtPubkey();
  privkey_ = ext_privkey.GetPrivkey();
  pubkey_ = privkey_.GetPubkey();
}

KeyData::KeyData(
    const ExtPubkey& ext_pubkey, const std::string& child_path,
    const ByteData& finterprint)
    : extpubkey_(ext_pubkey), fingerprint_(finterprint) {
  if (!child_path.empty()) {
    path_ = ToArrayFromString(child_path, "KeyData", 0);
  }
  pubkey_ = ext_pubkey.GetPubkey();
}

KeyData::KeyData(
    const Privkey& privkey, const std::string& child_path,
    const ByteData& finterprint)
    : privkey_(privkey), fingerprint_(finterprint) {
  if (!child_path.empty()) {
    path_ = ToArrayFromString(child_path, "KeyData", 0);
  }
  pubkey_ = privkey.GetPubkey();
}

KeyData::KeyData(
    const Pubkey& pubkey, const std::string& child_path,
    const ByteData& finterprint)
    : pubkey_(pubkey), fingerprint_(finterprint) {
  if (!child_path.empty()) {
    path_ = ToArrayFromString(child_path, "KeyData", 0);
  }
}

KeyData::KeyData(
    const ExtPrivkey& ext_privkey, const std::vector<uint32_t>& child_num_list,
    const ByteData& finterprint)
    : extprivkey_(ext_privkey),
      path_(child_num_list),
      fingerprint_(finterprint) {
  extpubkey_ = ext_privkey.GetExtPubkey();
  privkey_ = ext_privkey.GetPrivkey();
  pubkey_ = privkey_.GetPubkey();
}

KeyData::KeyData(
    const ExtPubkey& ext_pubkey, const std::vector<uint32_t>& child_num_list,
    const ByteData& finterprint)
    : extpubkey_(ext_pubkey),
      path_(child_num_list),
      fingerprint_(finterprint) {
  pubkey_ = ext_pubkey.GetPubkey();
}

KeyData::KeyData(
    const Privkey& privkey, const std::vector<uint32_t>& child_num_list,
    const ByteData& finterprint)
    : privkey_(privkey), path_(child_num_list), fingerprint_(finterprint) {
  pubkey_ = privkey.GetPubkey();
}

KeyData::KeyData(
    const Pubkey& pubkey, const std::vector<uint32_t>& child_num_list,
    const ByteData& finterprint)
    : pubkey_(pubkey), path_(child_num_list), fingerprint_(finterprint) {
  // do nothing
}

KeyData::KeyData(
    const std::string& path_info, int32_t child_num, bool has_schnorr_pubkey) {
  auto key_info = path_info;
  if (path_info[0] == '[') {
    // key origin information check. cut to ']'
    auto pos = path_info.find("]");
    if (pos != std::string::npos) {
      key_info = path_info.substr(pos + 1);
      auto path = path_info.substr(1, pos - 1);
      pos = path.find("/");
      if (pos != std::string::npos) {
        if (pos != 0) {
          auto fingerprint = path.substr(0, pos);
          fingerprint_ = ByteData(fingerprint);
        }
        auto child_path = path.substr(pos + 1);
        path_ = ToArrayFromString(child_path, "KeyData", 0);
      }
    }
  }
  // derive key check (xpub,etc)D
  std::string hdkey_top;
  if (key_info.size() > 4) hdkey_top = key_info.substr(1, 3);
  if ((hdkey_top == "pub") || (hdkey_top == "prv")) {
    std::string path;
    std::string key;
    bool has_end_any_hardened = false;
    bool exist_hardened = false;
    std::vector<std::string> list = StringUtil::Split(key_info, "/");
    key = list[0];
    if (list.size() > 1) {
      size_t index;
      for (index = 1; index < list.size(); ++index) {
        if (index != 1) path += "/";
        if (list[index] == "*") break;
        if ((list[index] == "*'") || (list[index] == "*h") ||
            (list[index] == "*H")) {
          has_end_any_hardened = true;
          exist_hardened = true;
          break;
        }
        path += list[index];
        if ((list[index].find("'") != std::string::npos) ||
            (list[index].find("h") != std::string::npos) ||
            (list[index].find("H") != std::string::npos)) {
          exist_hardened = true;
        } else {
          auto value = strtoul(list[index].c_str(), nullptr, 0);
          if (value >= 0x80000000) exist_hardened = true;
        }
      }
      if ((index + 1) < list.size()) {
        warn(
            CFD_LOG_SOURCE,
            "Failed to extkey path. "
            "A '*' can only be specified at the end.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            "Failed to extkey path. "
            "A '*' can only be specified at the end.");
      }
      if (list.back().find("*") != std::string::npos) {
        if (child_num < 0) {
          warn(
              CFD_LOG_SOURCE,
              "Failed to extkey path. "
              "A '*' can not support.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError,
              "Failed to extkey path. "
              "A '*' can not support.");
        }
        path += std::to_string(child_num);
        if (has_end_any_hardened) path += "h";
      }
    }
    std::string base_extkey_;
    if (hdkey_top == "prv") {
      extprivkey_ = ExtPrivkey(key);
      if (!path.empty()) extprivkey_ = extprivkey_.DerivePrivkey(path);
      extpubkey_ = extprivkey_.GetExtPubkey();
      privkey_ = extprivkey_.GetPrivkey();
      pubkey_ = privkey_.GetPubkey();
    } else if (exist_hardened) {
      warn(
          CFD_LOG_SOURCE, "Failed to extPubkey. hardened is extPrivkey only.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to extPubkey. hardened is extPrivkey only.");
    } else {
      extpubkey_ = ExtPubkey(key);
      if (!path.empty()) extpubkey_ = extpubkey_.DerivePubkey(path);
      pubkey_ = extpubkey_.GetPubkey();
    }
    if (!path.empty()) {
      auto path_list = ToArrayFromString(path, "KeyData", 0);
      path_.reserve(path_.size() + path_list.size());
      std::copy(path_list.begin(), path_list.end(), std::back_inserter(path_));
    }
  } else if (Privkey::HasWif(key_info)) {
    privkey_ = Privkey::FromWif(key_info);
    pubkey_ = privkey_.GetPubkey();
  } else {
    ByteData bytes(key_info);
    if (Pubkey::IsValid(bytes)) {
      pubkey_ = Pubkey(bytes);
    } else if (has_schnorr_pubkey) {
      SchnorrPubkey schnorr_pubkey(bytes);
      pubkey_ = schnorr_pubkey.CreatePubkey();
    } else {
      privkey_ = Privkey(bytes);
      pubkey_ = privkey_.GetPubkey();
    }
  }
}

bool KeyData::IsValid() const { return pubkey_.IsValid(); }

bool KeyData::HasExtPrivkey() const { return extprivkey_.IsValid(); }

bool KeyData::HasExtPubkey() const { return extpubkey_.IsValid(); }

bool KeyData::HasPrivkey() const { return privkey_.IsValid(); }

Pubkey KeyData::GetPubkey() const { return pubkey_; }

Privkey KeyData::GetPrivkey() const { return privkey_; }

ExtPrivkey KeyData::GetExtPrivkey() const { return extprivkey_; }

ExtPubkey KeyData::GetExtPubkey() const { return extpubkey_; }

ByteData KeyData::GetFingerprint() const { return fingerprint_; }

std::vector<uint32_t> KeyData::GetChildNumArray() const { return path_; }

KeyData KeyData::DerivePrivkey(
    std::vector<uint32_t> path, bool has_rebase_path) const {
  if (!extprivkey_.IsValid()) {
    warn(CFD_LOG_SOURCE, "Failed to invalid extPrivkey.");
    throw CfdException(
        CfdError::kCfdIllegalStateError, "Failed to invalid extPrivkey.");
  }
  ExtPrivkey key = extprivkey_.DerivePrivkey(path);
  if (has_rebase_path) {
    auto fp = extprivkey_.GetPrivkey().GeneratePubkey().GetFingerprint();
    return KeyData(key, path, fp);
  } else {
    auto join_path = path_;
    join_path.reserve(join_path.size() + path.size());
    std::copy(path.begin(), path.end(), std::back_inserter(join_path));
    return KeyData(key, join_path, fingerprint_);
  }
}

KeyData KeyData::DerivePrivkey(std::string path, bool has_rebase_path) const {
  auto arr = ToArrayFromString(path, "KeyData::DerivePrivkey", 0);
  return DerivePrivkey(arr, has_rebase_path);
}

KeyData KeyData::DerivePubkey(
    std::vector<uint32_t> path, bool has_rebase_path) const {
  if (extprivkey_.IsValid()) {
    auto key = extprivkey_.DerivePubkey(path);
    if (has_rebase_path) {
      auto fp = extprivkey_.GetPrivkey().GeneratePubkey().GetFingerprint();
      return KeyData(key, path, fp);
    } else {
      auto join_path = path_;
      join_path.reserve(join_path.size() + path.size());
      std::copy(path.begin(), path.end(), std::back_inserter(join_path));
      return KeyData(key, join_path, fingerprint_);
    }
  } else if (extpubkey_.IsValid()) {
    auto key = extpubkey_.DerivePubkey(path);
    if (has_rebase_path) {
      auto fp = extpubkey_.GetPubkey().GetFingerprint();
      return KeyData(key, path, fp);
    } else {
      auto join_path = path_;
      join_path.reserve(join_path.size() + path.size());
      std::copy(path.begin(), path.end(), std::back_inserter(join_path));
      return KeyData(key, join_path, fingerprint_);
    }
  } else {
    warn(CFD_LOG_SOURCE, "Failed to invalid extPubkey.");
    throw CfdException(
        CfdError::kCfdIllegalStateError, "Failed to invalid extPubkey.");
  }
}

KeyData KeyData::DerivePubkey(std::string path, bool has_rebase_path) const {
  auto arr = ToArrayFromString(path, "KeyData::DerivePubkey", 0);
  return DerivePubkey(arr, has_rebase_path);
}

std::string KeyData::GetBip32Path(
    HardenedType hardened_type, bool has_hex) const {
  std::stringstream ss;
  bool is_first = true;
  for (auto child_num : path_) {
    if (!is_first) ss << "/";
    uint32_t num = (hardened_type == HardenedType::kNumber)
                       ? child_num
                       : (child_num & 0x7FFFFFFF);
    if (has_hex) {
      ss << "0x" << std::hex << num;
    } else {
      ss << num;
    }

    if (child_num & 0x80000000) {
      switch (hardened_type) {
        case kLargeH:
          ss << "H";
          break;
        case kSmallH:
          ss << "h";
          break;
        case kNumber:
          // do nothing
          break;
        case kApostrophe:
        default:
          ss << "'";
          break;
      }
    }
    is_first = false;
  }
  return ss.str();
}

std::string KeyData::ToString(
    bool has_pubkey, HardenedType hardened_type, bool has_hex) const {
  auto path_str = GetBip32Path(hardened_type, has_hex);
  std::stringstream ss;
  if ((!path_str.empty()) && (!fingerprint_.IsEmpty())) {
    ss << "[" << fingerprint_.GetHex() << "/" << path_str << "]";
  }
  if (has_pubkey) {
    ss << pubkey_.GetHex();
  } else if (extprivkey_.IsValid()) {
    ss << extprivkey_.ToString();
  } else if (extpubkey_.IsValid()) {
    ss << extpubkey_.ToString();
  } else if (privkey_.IsValid()) {
    ss << privkey_.GetWif();
  } else {
    ss << pubkey_.GetHex();
  }
  return ss.str();
}

}  // namespace core
}  // namespace cfd
