// Copyright 2020 CryptoGarage
/**
 * @file cfdcore_psbt.h
 *
 * @brief This file is defines Partially Signed Bitcoin Transaction.
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_PSBT_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_PSBT_H_

#include <cstddef>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_transaction.h"

namespace cfd {
namespace core {

/**
 * @brief The class of Partially Signed Bitcoin Transaction.
 */
class CFD_CORE_EXPORT Psbt {
 public:
  /**
   * @brief constructor.
   *
   * for List.
   */
  Psbt();
  /**
   * @brief constructor
   * @param[in] psbt_version  psbt version
   * @param[in] version       tx version
   * @param[in] lock_time     lock time
   */
  explicit Psbt(uint32_t psbt_version, uint32_t version, uint32_t lock_time);
  /**
   * @brief constructor
   * @param[in] base64    base64 string.
   */
  explicit Psbt(const std::string& base64);
  /**
   * @brief constructor
   * @param[in] byte_data   byte data
   */
  explicit Psbt(const ByteData& byte_data);
  /**
   * @brief constructor
   * @param[in] psbt_version  psbt version
   * @param[in] transaction   Transaction object.
   */
  explicit Psbt(uint32_t psbt_version, const Transaction& transaction);
  /**
   * @brief constructor
   * @param[in] transaction   Psbt object.
   */
  explicit Psbt(const Psbt& transaction);
  /**
   * @brief destructor
   */
  virtual ~Psbt() { Psbt::FreeWallyPsbtAddress(wally_psbt_pointer_); }

  /**
   * @brief copy constructor.
   * @param[in] transaction   Psbt object.
   * @return Psbt object.
   */
  Psbt& operator=(const Psbt& transaction) &;

  std::string GetBase64() const;

  ByteData GetData() const;

  uint32_t GetDataSize() const;

  /**
   * @brief check finalized.
   * @retval true   already finalized.
   * @retval false  not finalized.
   */
  bool IsFinalized() const;

  /**
   * @brief check finalized input.
   * @param[in] index   txin index.
   * @retval true   already finalized input.
   * @retval false  not finalized input.
   */
  bool IsFinalizedInput(uint32_t index) const;

  void Finalize();

  ByteData Extract() const;
  Transaction ExtractTransaction() const;

  void Combine(const Psbt& transaction);

  void Sign(const Privkey& privkey, bool has_grind_r = true);

  void Join(const Psbt& transaction, bool ignore_duplicate_error = false);

  uint32_t AddTxIn(const TxIn &txin);
  uint32_t AddTxIn(const TxInReference &txin);
  uint32_t AddTxIn(const Txid &txid, uint32_t vout,
      uint32_t sequence);

  void SetTxInUtxo(uint32_t index, const Transaction& tx, const KeyData& key);
  void SetTxInUtxo(uint32_t index, const Transaction& tx, const Script &redeem_script, const KeyData& key);
  void SetTxInUtxo(uint32_t index, const Transaction& tx, const Script &redeem_script, const std::vector<KeyData>& key_list);
  void SetTxInUtxo(uint32_t index, const TxOutReference& txout, const KeyData& key);
  void SetTxInUtxo(uint32_t index, const TxOutReference& txout, const Script &redeem_script, const KeyData& key);
  void SetTxInUtxo(uint32_t index, const TxOutReference& txout, const Script &redeem_script, const std::vector<KeyData>& key_list);
  void SetTxInSignature(uint32_t index, const KeyData& key, const ByteData& signature);
  void SetTxInSighashType(uint32_t index, const SigHashType& sighash_type);
  void SetTxInFinalScript(uint32_t index, const std::vector<ByteData>& unlocking_script);
  void SetTxInProprietary(uint32_t index, const ByteData& key, const ByteData& value);

  Transaction GetTxInUtxoFull(uint32_t index, bool ignore_error = false, bool* is_witness = nullptr) const;
  TxOut GetTxInUtxo(uint32_t index, bool ignore_error = false, bool* is_witness = nullptr) const;
  Script GetTxInRedeemScript(uint32_t index, bool ignore_error = false, bool* is_witness = nullptr) const;
  std::vector<KeyData> GetTxInKeyDataList(uint32_t index) const;
  KeyData GetTxInKeyData(uint32_t index, bool ignore_error = false) const;
  std::vector<Pubkey> GetTxInSignaturePubkeyList(uint32_t index) const;
  ByteData GetTxInSignature(uint32_t index, const Pubkey& pubkey) const;
  bool IsFindTxInSignature(uint32_t index, const Pubkey& pubkey) const;
  SigHashType GetTxInSighashType(uint32_t index) const;
  bool IsFindTxInSighashType(uint32_t index) const;
  std::vector<ByteData> GetTxInFinalScript(uint32_t index, bool is_witness_stack = true) const;
  ByteData GetTxInProprietary(uint32_t index, const ByteData& key) const;
  bool IsFindTxInProprietary(uint32_t index, const ByteData& key) const;


  uint32_t AddTxOut(const TxOut &txout);
  uint32_t AddTxOut(const TxOutReference &txout);
  uint32_t AddTxOut(const Script &locking_script, const Amount &amount);
  void SetTxOutData(uint32_t index, const KeyData& key);
  void SetTxOutData(uint32_t index, const Script &redeem_script, const KeyData& key);
  void SetTxOutData(uint32_t index, const Script &redeem_script, const std::vector<KeyData>& key_list);
  void SetTxOutProprietary(uint32_t index, const ByteData& key, const ByteData& value);
  
  Script GetTxOutScript(uint32_t index, bool ignore_error = false, bool* is_witness = nullptr) const;
  KeyData GetTxOutKeyData(uint32_t index, bool ignore_error = false) const;
  std::vector<KeyData> GetTxOutKeyDataList(uint32_t index) const;
  ByteData GetTxOutProprietary(uint32_t index, const ByteData& key) const;
  bool IsFindTxOutProprietary(uint32_t index, const ByteData& key) const;


  void SetGlobalProprietary(const ByteData& key, const ByteData& value);
  ByteData GetGlobalProprietary(const ByteData& key) const;
  bool IsFindGlobalProprietary(const ByteData& key) const;

 protected:
  void* wally_psbt_pointer_;  ///< libwally psbt pointer
  Transaction base_tx_;       ///< base transaction

  /**
   * @brief Free a heap address for libwally-core psbt object.
   * @param[in] wally_psbt_pointer  address
   */
  static void FreeWallyPsbtAddress(const void* wally_psbt_pointer);
  /**
   * @brief Rebuild base transaction.
   * @param[in] wally_psbt_pointer  address
   * @return Transaction
   */
  static Transaction RebuildTransaction(const void* wally_psbt_pointer);

 private:
  /**
   * @brief TxIn配列のIndex範囲をチェックする.
   * @param[in] index     TxIn配列のIndex値
   * @param[in] line      行数
   * @param[in] caller    コール元関数名
   */
  virtual void CheckTxInIndex(
      uint32_t index, int line, const char* caller) const;
  /**
   * @brief TxOut配列のIndex範囲をチェックする.
   * @brief check TxOut array range.
   * @param[in] index     TxOut配列のIndex値
   * @param[in] line      行数
   * @param[in] caller    コール元関数名
   */
  virtual void CheckTxOutIndex(
      uint32_t index, int line, const char* caller) const;
 #if 0
  /**
   * @brief witness stackに情報を追加する.
   * @param[in] tx_in_index   TxIn配列のindex値
   * @param[in] data          witness stackに追加するバイトデータ
   * @return witness stack
   */
  const ScriptWitness AddScriptWitnessStack(
      uint32_t tx_in_index, const std::vector<uint8_t>& data);
  /**
   * @brief witness stackの指定index位置を更新する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] witness_index     witness stackのindex位置
   * @param[in] data              witness stackに追加する32byte情報
   * @return witness stack
   */
  const ScriptWitness SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index,
      const std::vector<uint8_t>& data);
  /**
   * @brief Transactionのバイトデータを取得する.
   * @param[in] has_witness   witnessを含めるかのフラグ
   * @return バイトデータ
   */
  ByteData GetByteData(bool has_witness) const;
  /**
   * @brief 配列をByteDataへと変換する.
   * @param[in] data      buffer
   * @param[in] size      size
   * @return ByteData
   */
  static ByteData ConvertToByteData(const uint8_t* data, size_t size);
#endif
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_PSBT_H_
