// Copyright 2020 CryptoGarage
/**
 * @file cfdcore_key.h
 *
 * @brief definition for Pubkey/Privkey class
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_KEY_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_KEY_H_

#include <map>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"

namespace cfd {
namespace core {

//! Bitcoin message magic string.
constexpr const char *const kBitcoinMessageMagic = "Bitcoin Signed Message:\n";

/**
 * @typedef NetType
 * @brief definition for Bitcoin/Liquid network.
 */
typedef enum {
  kMainnet = 0,               //!< MAINNET
  kTestnet,                   //!< TESTNET
  kRegtest,                   //!< REGTEST
  kLiquidV1,                  //!< LiquidV1
  kElementsRegtest,           //!< Elements Regtest
  kCustomChain,               //!< Custom chain
  kNetTypeNum = kCustomChain  //!< NETTYPE_NUM
} NetType;

/**
 * @brief Version pair struct.
 */
struct ExtkeyVersionPair {
  uint32_t pubkey_version;   //!< pubkey version
  uint32_t privkey_version;  //!< privkey version
};

/**
 * @brief bip32 version format type.
 */
enum Bip32FormatType {
  kNormal = 0,  //!< normal (bip32)
  kBip49 = 1,   //!< BIP 0049 (P2SH-P2WPKH)
  kBip84 = 2,   //!< BIP 0084 (P2WPKH)
};

//! key format key name: isMainnet (value is empty or "true")
constexpr const char *const kKeytypeIsMainnet = "IsMainnet";
//! key format key name: WIF prefix
constexpr const char *const kWifPrefix = "wif";
//! key format key name: bip32 xpub version
constexpr const char *const kBip32Xpub = "bip32xpub";
//! key format key name: bip32 xprv version
constexpr const char *const kBip32Xprv = "bip32xprv";
//! key format key name: bip49 ypub version
constexpr const char *const kBip49Ypub = "bip49ypub";
//! key format key name: bip49 yprv version
constexpr const char *const kBip49Yprv = "bip49yprv";
//! key format key name: bip84 zpub version
constexpr const char *const kBip84Zpub = "bip84zpub";
//! key format key name: bip84 zprv version
constexpr const char *const kBip84Zprv = "bip84zprv";

/**
 * @class KeyFormatData
 * @brief class for showing format data of address
 */
class CFD_CORE_EXPORT KeyFormatData {
 public:
  /**
   * @brief constructor.
   */
  KeyFormatData();
  /**
   * @brief constructor.
   * @param[in] is_mainnet_on_default     default mainnet flag
   */
  explicit KeyFormatData(bool is_mainnet_on_default);
  /**
   * @brief constructor.
   * @param[in] map_data     prefix setting map
   */
  explicit KeyFormatData(const std::map<std::string, std::string> &map_data);
  /**
   * @brief copy constructor.
   * @param[in] object    KeyFormatData object
   */
  KeyFormatData(const KeyFormatData &object);
  /**
   * @brief copy constructor.
   * @param[in] object    KeyFormatData object
   * @return KeyFormatData object
   */
  KeyFormatData &operator=(const KeyFormatData &object);

  /**
   * @brief Check exist key.
   * @param[in] key   mapping key
   * @retval true   exist
   * @retval false  not exist
   */
  bool IsFind(const std::string &key) const;
  /**
   * @brief Get string value.
   * @param[in] key   mapping key
   * @return value
   */
  std::string GetString(const std::string &key) const;
  /**
   * @brief Get numeric value from string.
   * @param[in] key   mapping key
   * @return uint32_t value
   */
  uint32_t GetValue(const std::string &key) const;

  /**
   * @brief Get WIF prefix.
   * @return uint8_t value
   */
  uint32_t GetWifPrefix() const;
  /**
   * @brief Get Extkey version pair.
   * @param[in] version   extkey version
   * @return Version pair struct.
   */
  ExtkeyVersionPair GetVersionPair(uint32_t version) const;
  /**
   * @brief Get Extkey version pair.
   * @param[in] format_type   format type.
   * @return Version pair struct.
   */
  ExtkeyVersionPair GetVersionPair(Bip32FormatType format_type) const;
  /**
   * @brief Get Extkey version format type.
   * @param[in] version   extkey version
   * @return format type.
   */
  Bip32FormatType GetVersionFormatType(uint32_t version) const;
  /**
   * @brief Find relational extkey version.
   * @param[in] version   extkey version
   * @retval true   find.
   * @retval false  not found.
   */
  bool IsFindVersion(uint32_t version) const;
  /**
   * @brief Find relational format type.
   * @param[in] format_type   format type.
   * @retval true   find.
   * @retval false  not found.
   */
  bool IsFindFormatType(Bip32FormatType format_type) const;

  /**
   * @brief Get network type.
   * @return network type
   */
  NetType GetNetType() const;
  /**
   * @brief Check mainnet data.
   * @retval true   mainnet
   * @retval false  testnet
   */
  bool IsMainnet() const;

  /**
   * @brief Check format item.
   * @retval true   valid
   * @retval false  invalid
   */
  bool IsValid() const;

  /**
   * @brief Load cache.
   * @retval true   valid
   * @retval false  invalid
   */
  bool LoadCache();

  /**
   * @brief Get Address format data from json string.
   * @param[in] json_data       json string
   * @return Address format data
   */
  static KeyFormatData ConvertFromJson(const std::string &json_data);
  /**
   * @brief Get Address format data list from json string.
   * @param[in] json_data       json string
   * @return Address format data list
   */
  static std::vector<KeyFormatData> ConvertListFromJson(
      const std::string &json_data);

 private:
  std::map<std::string, std::string> map_;  //!< map
  // cache values
  bool is_mainnet = false;            //!< mainnet flag cache
  uint8_t wif_prefix_ = 0;            //!< wif prefix cache
  std::vector<bool> has_format_;      //!< enable format list
  ExtkeyVersionPair bip32_ = {0, 0};  //!< bip32 prefix cache
  ExtkeyVersionPair bip49_ = {0, 0};  //!< bip32 prefix cache
  ExtkeyVersionPair bip84_ = {0, 0};  //!< bip32 prefix cache
};

/**
 * @brief Get key format list.
 * @return key format list.
 */
CFD_CORE_API std::vector<KeyFormatData> GetKeyFormatList();

/**
 * @brief Get key format data.
 * @param[in] net_type    network type
 * @return key format data.
 */
CFD_CORE_API KeyFormatData GetKeyFormatData(NetType net_type);

/**
 * @brief Get key format data.
 * @param[in] is_mainnet    mainnet flag
 * @return key format data.
 */
CFD_CORE_API KeyFormatData GetKeyFormatData(bool is_mainnet);

/**
 * @brief set custom key format list.
 * @param[in] list    custom key format list.
 */
CFD_CORE_API void SetCustomKeyFormatList(
    const std::vector<KeyFormatData> &list);

/**
 * @brief clear custom key format list.
 */
CFD_CORE_API void ClearCustomKeyFormatList();

/**
 * @brief Data class representing PublicKey
 */
class CFD_CORE_EXPORT Pubkey {
 public:
  /**
   * @brief Uncompress Pubkey byte size
   */
  static constexpr uint32_t kPubkeySize = 65;
  /**
   * @brief Compress Pubkey byte size
   */
  static constexpr uint32_t kCompressedPubkeySize = 33;

  /**
   * @brief constructor
   */
  Pubkey();

  /**
   * @brief constructor
   * @param[in] byte_data   Public key ByteData instance
   */
  explicit Pubkey(ByteData byte_data);

  /**
   * @brief constructor
   * @param[in] hex_string Public Key HEX string
   */
  explicit Pubkey(const std::string &hex_string);

  /**
   * @brief Get HEX string.
   * @return HEX string.
   */
  std::string GetHex() const;

  /**
   * @brief Get ByteData instance.
   * @return ByteData
   */
  ByteData GetData() const;

  /**
   * @brief Returns whether the public key is in Compress format.
   * @retval true  compressed key.
   * @retval false uncompressed key.
   */
  bool IsCompress() const;

  /**
   * @brief Get y-parity flag.
   * @details This function is enable on compressed pubkey only.
   * @return parity bit
   */
  bool IsParity() const;

  /**
   * @brief Verify that the public key is in the correct format.
   * @retval true   valid format
   * @retval false  invalid format
   */
  bool IsValid() const;

  /**
   * @brief Check if the public keys match.
   * @param[in] pubkey check target Pubkey
   * @retval true   equal
   * @retval false  not equal
   */
  bool Equals(const Pubkey &pubkey) const;

  /**
   * @brief Get fingerprint.
   * @param[in] get_size    get fingerprint size.
   * @return fingerprint
   */
  ByteData GetFingerprint(uint32_t get_size = 4) const;

  /**
   * @brief Combine pubkeys.
   * @param[in] pubkeys Pubkey list
   * @return Combined pubkey
   */
  static Pubkey CombinePubkey(const std::vector<Pubkey> &pubkeys);

  /**
   * @brief Combine pubkey.
   * @param[in] pubkey base pubkey
   * @param[in] message_key combine pubkey
   * @return Combined pubkey
   */
  static Pubkey CombinePubkey(const Pubkey &pubkey, const Pubkey &message_key);

  /**
   * @brief Create new public key with tweak added.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of pubkey.
   * @param[in] tweak     tweak to be added
   * @return new instance of pubkey key with tweak added.
   */
  Pubkey CreateTweakAdd(const ByteData256 &tweak) const;

  /**
   * @brief Create new negated public key with tweak multiplied.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of pubkey.
   * @param[in] tweak     tweak to be added
   * @return new instance of pubkey key with tweak added.
   */
  Pubkey CreateTweakMul(const ByteData256 &tweak) const;

  /**
   * @brief Create new negated public key.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of pubkey.
   * @return new instance of pubkey key with tweak added.
   */
  Pubkey CreateNegate() const;

  /**
   * @brief Create new uncompressed public key.
   * @return new instance of pubkey key with uncompressed.
   */
  Pubkey Compress() const;

  /**
   * @brief Create new uncompressed public key.
   * @return new instance of pubkey key with uncompressed.
   */
  Pubkey Uncompress() const;

  /**
   * @brief Verify if a signature with respect to a public key and a message.
   * @param[in] signature_hash  the message to verify the signature against.
   * @param[in] signature       the signature to verify.
   * @return true if the signature is valid, false if not.
   */
  bool VerifyEcSignature(
      const ByteData256 &signature_hash, const ByteData &signature) const;

  /**
   * @brief Verify bitcoin message's signature.
   * @param[in] signature   message signature
   * @param[in] message     message
   * @param[out] pubkey     recovery pubkey
   * @return true if the signature is valid, false if not.
   */
  bool VerifyBitcoinMessage(
      const ByteData &signature, const std::string &message,
      Pubkey *pubkey = nullptr) const;
  /**
   * @brief Verify bitcoin message's signature.
   * @param[in] base64_signature  message signature with base64.
   * @param[in] message           message
   * @param[out] pubkey           recovery pubkey
   * @return true if the signature is valid, false if not.
   */
  bool VerifyBitcoinMessageWithBase64(
      const std::string &base64_signature, const std::string &message,
      Pubkey *pubkey = nullptr) const;
  /**
   * @brief Verify message's signature.
   * @param[in] signature       message signature
   * @param[in] message         message
   * @param[in] message_magic   magic string
   * @param[out] pubkey         recovery pubkey
   * @return true if the signature is valid, false if not.
   */
  bool VerifyMessage(
      const ByteData &signature, const std::string &message,
      const std::string &message_magic, Pubkey *pubkey = nullptr) const;

  /**
   * @brief Verify that the public key is in the correct format.
   * @param[in] byte_data pubkey bytedata
   * @retval true   valid format
   * @retval false  invalid format
   */
  static bool IsValid(const ByteData &byte_data);

  /**
   * @brief Compare the HEX values ​​of the two specified public keys.
   * @param[in] source        source target
   * @param[in] destination   destination target
   * @retval true   Large
   * @retval false  Small
   */
  static bool IsLarge(const Pubkey &source, const Pubkey &destination);

  /**
   * @brief combine pubkey.
   * @param[in] right   pubkey data
   * @return combined pubkey
   */
  Pubkey operator+=(const Pubkey &right);
  /**
   * @brief tweak add pubkey.
   * @param[in] right   tweak data
   * @return tweaked pubkey
   */
  Pubkey operator+=(const ByteData256 &right);
  /**
   * @brief negate and tweak add for pubkey.
   * @param[in] right   tweak data (before negate)
   * @return tweaked pubkey
   */
  Pubkey operator-=(const ByteData256 &right);
  /**
   * @brief tweak mul for pubkey.
   * @param[in] right   tweak data
   * @return tweaked pubkey
   */
  Pubkey operator*=(const ByteData256 &right);

 private:
  /**
   * @brief ByteData of PublicKey
   */
  ByteData data_;
};

/**
 * @brief Data class representing Private Key
 */
class CFD_CORE_EXPORT Privkey {
 public:
  /**
   * @brief Private key byte size
   */
  static constexpr uint32_t kPrivkeySize = 32;  // EC_PRIVATE_KEY_LEN
  /**
   * @brief default constructor.
   */
  Privkey();

  /**
   * @brief constructor.
   * @param[in] byte_data ByteData object.
   * @param[in] net_type Mainnet or Testnet
   * @param[in] is_compressed pubkey compressed flag.
   */
  explicit Privkey(
      const ByteData &byte_data, NetType net_type = NetType::kMainnet,
      bool is_compressed = true);

  /**
   * @brief constructor.
   * @param[in] byte_data ByteData object.
   * @param[in] net_type Mainnet or Testnet
   * @param[in] is_compressed pubkey compressed flag.
   */
  explicit Privkey(
      const ByteData256 &byte_data, NetType net_type = NetType::kMainnet,
      bool is_compressed = true);

  /**
   * @brief constructor.
   * @param[in] hex_str PrivateKey HEX string
   * @param[in] net_type Mainnet or Testnet
   * @param[in] is_compressed pubkey compressed flag.
   */
  explicit Privkey(
      const std::string &hex_str, NetType net_type = NetType::kMainnet,
      bool is_compressed = true);

  /**
   * @brief Get HEX string.
   * @return HEX string
   */
  std::string GetHex() const;

  /**
   * @brief Get ByteData instance.
   * @return ByteData
   */
  ByteData GetData() const;

  /**
   * @brief Convert to WIF.
   * @param[in] net_type Mainnet or Testnet
   * @param[in] is_compressed   pubkey compressed flag.
   * @return WIF
   */
  std::string ConvertWif(NetType net_type, bool is_compressed = true) const;
  /**
   * @brief Get Wallet Import Format from member value.
   * @return WIF
   */
  std::string GetWif() const;

  /**
   * @brief Generate pubkey to privkey.
   * @param[in] is_compressed   pubkey compressed flag.
   * @return Pubkey
   */
  Pubkey GeneratePubkey(bool is_compressed = true) const;

  /**
   * @brief get pubkey from privkey.
   * @return Pubkey
   */
  Pubkey GetPubkey() const;

  /**
   * @brief Create new private key with tweak added.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @param[in] tweak     tweak to be added
   * @return new instance of private key with tweak added.
   */
  Privkey CreateTweakAdd(const ByteData256 &tweak) const;
  /**
   * @brief Create new private key with tweak added.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @param[in] tweak     tweak to be added
   * @return new instance of private key with tweak added.
   */
  Privkey CreateTweakAdd(const Privkey &tweak) const;

  /**
   * @brief Create new private key with tweak multiplied.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @param[in] tweak     tweak to be added
   * @return new instance of private key with tweak added.
   */
  Privkey CreateTweakMul(const ByteData256 &tweak) const;
  /**
   * @brief Create new private key with tweak multiplied.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @param[in] tweak     tweak to be added
   * @return new instance of private key with tweak added.
   */
  Privkey CreateTweakMul(const Privkey &tweak) const;

  /**
   * @brief Create new negated private key.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @return new instance of private key with tweak added.
   */
  Privkey CreateNegate() const;

  /**
   * @brief Returns whether the private key setting status is invalid.
   * @retval true invalid
   * @retval false valid
   * @deprecated Scheduled to be deleted when organizing API
   */
  bool IsInvalid() const;

  /**
   * @brief Returns whether the Private Key setting status is normal.
   * @retval true  valid
   * @retval false invalid
   */
  bool IsValid() const;

  /**
   * @brief Check this privkey and argument key byte is match or not.
   * @param[in] privkey   private key to be compared
   * @retval true   match
   * @retval false  not match
   */
  bool Equals(const Privkey &privkey) const;

  /**
   * @brief calculate ec signature from sighash.
   * @param[in] signature_hash  signature hash
   * @param[in] has_grind_r     use EC_FLAG_GRIND_R.(default: true)
   * @return signature
   */
  ByteData CalculateEcSignature(
      const ByteData256 &signature_hash, bool has_grind_r = true) const;

  /**
   * @brief Sign bitcoin message.
   * @param[in] message message
   * @return signature
   */
  ByteData SignBitcoinMessage(const std::string &message) const;
  /**
   * @brief Sign bitcoin message and output base64 encoding string.
   * @param[in] message message
   * @return base64 encoding signature
   */
  std::string SignBitcoinMessageWithBase64(const std::string &message) const;
  /**
   * @brief Sign message.
   * @param[in] message message
   * @param[in] message_magic   magic string
   * @return signature
   */
  ByteData SignMessage(
      const std::string &message, const std::string &message_magic) const;

  /**
   * @brief set pubkey compressed flag.
   * @param[in] is_compressed  pubkey compressed.
   */
  void SetPubkeyCompressed(bool is_compressed);
  /**
   * @brief set network type.
   * @param[in] net_type  network type.
   */
  void SetNetType(NetType net_type);

  /**
   * @brief Generate privkey from WIF.
   * @param[in] wif WIF
   * @param[in] net_type Mainnet or Testnet
   * @param[in] is_compressed  pubkey compress flag.
   * @return Privkey
   */
  static Privkey FromWif(
      const std::string &wif, NetType net_type = NetType::kCustomChain,
      bool is_compressed = true);

  /**
   * @brief Generate Privkey from random numbers.
   *
   * It may take some time because it repeats until it can be generated.
   * @return Privkey
   */
  static Privkey GenerageRandomKey();

  /**
   * @brief check wif format.
   * @param[in] wif WIF string.
   * @param[out] net_type  network type. (Mainnet or Testnet)
   * @param[out] is_compressed  pubkey compressed.
   * @retval true   wallet import format.
   * @retval false  other format.
   */
  static bool HasWif(
      const std::string &wif, NetType *net_type = nullptr,
      bool *is_compressed = nullptr);

  /**
   * @brief tweak add privkey.
   * @param[in] right   tweak privkey
   * @return tweaked privkey
   */
  Privkey operator+=(const Privkey &right);
  /**
   * @brief tweak add privkey.
   * @param[in] right   tweak data
   * @return tweaked privkey
   */
  Privkey operator+=(const ByteData256 &right);
  /**
   * @brief negate and tweak add for privkey.
   * @param[in] right   tweak privkey (before negate)
   * @return tweaked privkey
   */
  Privkey operator-=(const Privkey &right);
  /**
   * @brief negate and tweak add for privkey.
   * @param[in] right   tweak data (before negate)
   * @return tweaked privkey
   */
  Privkey operator-=(const ByteData256 &right);
  /**
   * @brief tweak mul for privkey.
   * @param[in] right   tweak privkey
   * @return tweaked privkey
   */
  Privkey operator*=(const Privkey &right);
  /**
   * @brief tweak mul for privkey.
   * @param[in] right   tweak data
   * @return tweaked privkey
   */
  Privkey operator*=(const ByteData256 &right);

 private:
  /**
   * @brief ByteData of Private key.
   */
  ByteData data_;
  /**
   * @brief pubkey compressed.
   */
  bool is_compressed_ = true;
  /**
   * @brief network type. 
   */
  NetType net_type_ = NetType::kMainnet;

  /**
   * @brief Verify that it is in the correct format as a private key.
   * @param[in] buffer  ByteData of privkey.
   * @retval true   valid
   * @retval false  invalid
   */
  static bool IsValid(const std::vector<uint8_t> &buffer);
};

// global operator overloading

/**
 * @brief combine pubkey.
 * @param[in] left    base pubkey
 * @param[in] right   pubkey data
 * @return combined pubkey
 */
CFD_CORE_EXPORT Pubkey operator+(const Pubkey &left, const Pubkey &right);

/**
 * @brief tweak add pubkey.
 * @param[in] left    base pubkey
 * @param[in] right   tweak data
 * @return tweaked pubkey
 */
CFD_CORE_EXPORT Pubkey operator+(const Pubkey &left, const ByteData256 &right);
/**
 * @brief negate and tweak add for pubkey.
 * @param[in] left    base pubkey
 * @param[in] right   tweak data (before negate)
 * @return tweaked pubkey
 */
CFD_CORE_EXPORT Pubkey operator-(const Pubkey &left, const ByteData256 &right);
/**
 * @brief tweak mul for pubkey.
 * @param[in] left    base pubkey
 * @param[in] right   tweak data
 * @return tweaked pubkey
 */
CFD_CORE_EXPORT Pubkey operator*(const Pubkey &left, const ByteData256 &right);

/**
 * @brief tweak add privkey.
 * @param[in] left    base privkey
 * @param[in] right   tweak privkey
 * @return tweaked privkey
 */
CFD_CORE_EXPORT Privkey operator+(const Privkey &left, const Privkey &right);
/**
 * @brief tweak add privkey.
 * @param[in] left    base privkey
 * @param[in] right   tweak data
 * @return tweaked privkey
 */
CFD_CORE_EXPORT Privkey
operator+(const Privkey &left, const ByteData256 &right);
/**
 * @brief negate and tweak add for privkey.
 * @param[in] left    base privkey
 * @param[in] right   tweak privkey (before negate)
 * @return tweaked privkey
 */
CFD_CORE_EXPORT Privkey operator-(const Privkey &left, const Privkey &right);
/**
 * @brief negate and tweak add for privkey.
 * @param[in] left    base privkey
 * @param[in] right   tweak data (before negate)
 * @return tweaked privkey
 */
CFD_CORE_EXPORT Privkey
operator-(const Privkey &left, const ByteData256 &right);
/**
 * @brief tweak mul for privkey.
 * @param[in] left    base privkey
 * @param[in] right   tweak privkey
 * @return tweaked privkey
 */
CFD_CORE_EXPORT Privkey operator*(const Privkey &left, const Privkey &right);
/**
 * @brief tweak mul for privkey.
 * @param[in] left    base privkey
 * @param[in] right   tweak data
 * @return tweaked privkey
 */
CFD_CORE_EXPORT Privkey
operator*(const Privkey &left, const ByteData256 &right);

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_KEY_H_
