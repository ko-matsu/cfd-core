// Copyright 2020 CryptoGarage
/**
 * @file cfdcore_psbt.cpp
 *
 * @brief This file is implements Partially Signed Bitcoin Transaction.
 */
#include <algorithm>
#include <limits>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_descriptor.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_psbt.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_secp256k1.h"   // NOLINT
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

using logger::info;
using logger::warn;

// -----------------------------------------------------------------------------
// File constants
// -----------------------------------------------------------------------------

/* PSBT Version number */
#define WALLY_PSBT_HIGHEST_VERSION 0

/* Ignore scriptsig and witness when adding an input */
#define WALLY_PSBT_FLAG_NON_FINAL 0x1

/* Key prefix for proprietary keys in our unknown maps */
#define PSBT_PROPRIETARY_TYPE 0xFC

#if 0
/*
- cfd-coreで実装する機能
  - パラメータ個別でのAdd/Edit/Remove
  - 結合系の動作
  - 処理途中でのTX出力
  - パス情報用のクラス作成
    - HDWalletに追加。むしろそちら側を拡張したい。
- cfdで実装する機能
  - OutPoint指定での登録
  - UTXO一括登録, 更新（utxoupdatepsbt）
  - FundRawTransaction
  - TX情報を直接設定するAPI（ただしOutput側のKey一覧は未設定）
  - decodepsbt, analyzepsbt
  - 署名関連
  - その他、bitcoin-cli相当の動作（converttopsbt、createpsbt）

- usecase
  - Creator
    - 初期TXを作成する。（Inputは空）
  - Updater
    - Inputを追加する。（各自にPSBTを送付して追加してもらう）
    - その後、Fund相当の処理を行う。
    - Base TXはここでFIXする。
  - Signer
    - Signを追加する。（各自にPSBTを送付して追加してもらう）
  - Combiner
    - Signerが署名したTXを結合する。
  - Input Finalizer
    - InputのFinalize処理
      - ここ、APIにした方が良いかもしれない。★
  - Transaction Extractor
    - export


{ "rawtransactions",    "decodepsbt",     &decodepsbt,       {"psbt"} },
{ "rawtransactions",    "analyzepsbt",    &analyzepsbt,      {"psbt"} },
{ "rawtransactions",    "createpsbt",     &createpsbt,       {"inputs","outputs","locktime","replaceable"} },
{ "rawtransactions",    "converttopsbt",  &converttopsbt,    {"hexstring","permitsigdata","iswitness"} },
{ "rawtransactions",    "joinpsbts",      &joinpsbts,        {"txs"} },
{ "rawtransactions",    "utxoupdatepsbt", &utxoupdatepsbt,   {"psbt"} },
{ "rawtransactions",    "combinepsbt",    &combinepsbt,      {"txs"} },
{ "rawtransactions",    "finalizepsbt",   &finalizepsbt,     {"psbt", "extract"} },

{ "wallet",           "walletcreatefundedpsbt", &walletcreatefundedpsbt,  {"inputs","outputs","locktime","options","bip32derivs","solving_data"} }, Creator and Updater
{ "wallet",           "walletprocesspsbt",      &walletprocesspsbt,       {"psbt","sign","sighashtype","bip32derivs"} },
{ "wallet",           "walletfillpsbtdata",     &walletfillpsbtdata,      {"psbt","bip32derivs"} },
{ "wallet",           "walletsignpsbt",         &walletsignpsbt,          {"psbt","sighashtype","imbalance_ok"} },

walletfillpsbtdata: bip32情報を付与してキーの追加？

*/
#endif

/// Definition of No Witness Transaction version
static constexpr uint32_t kTransactionVersionNoWitness = 0x40000000;


enum PsbtGlobalKey {
  kUnsignedTx = 0,
  kXpub = 1,
  kVersion = 0xfb,
  kGrobalProprietary = 0xfc,
};

enum PsbtInputKey {
  kNonWitnessUtxo = 0,
  kWitnessUtxo = 1,
  kPartialSig = 2,
  kSighashType = 3,
  kRedeemScript = 4,
  kWitnessScript = 5,
  kInputBip32Derivation = 6,
  kFinalScriptSig = 7,
  kFinalScriptWitness = 8,
  kInputProprietary = 0xfc,
};

enum PsbtOutputKey {
  kOutputRedeemScript = 0,
  kOutputWitnessScript = 1,
  kOutputBip32Derivation = 2,
  kOutputProprietary = 0xfc,
};


// -----------------------------------------------------------------------------
// Internal
// -----------------------------------------------------------------------------
ByteData ConvertTxDataFromWally(struct wally_tx *tx) {
  size_t witness_count = 0;
  int ret = wally_tx_get_witness_count(tx, &witness_count);
  if (ret != WALLY_OK) {
    wally_tx_free(tx);
    warn(CFD_LOG_SOURCE, "wally_tx_get_witness_count NG[{}]", ret);
    throw CfdException(kCfdIllegalStateError, "psbt witness count get error.");
  }

  uint32_t flags = (witness_count != 0) ? WALLY_TX_FLAG_USE_WITNESS : 0;
  size_t size = 0;
  ret = wally_tx_get_length(tx, flags, &size);
  if (ret != WALLY_OK) {
    wally_tx_free(tx);
    warn(CFD_LOG_SOURCE, "wally_tx_get_length NG[{}]", ret);
    throw CfdException(kCfdIllegalStateError, "psbt tx size get error.");
  }

  try {
    std::vector<uint8_t> buf(size);
    size = 0;
    ret = wally_tx_to_bytes(tx, flags, buf.data(), buf.size(), &size);
    wally_tx_free(tx);
    tx = nullptr;
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_tx_to_bytes NG[{}]", ret);
      throw CfdException(kCfdIllegalStateError, "psbt tx get error.");
    }
    return ByteData(buf.data(), static_cast<uint32_t>(size));
  } catch (const CfdError &except) {
    throw except;
  } catch (...) {
    // from std::vector
    wally_tx_free(tx);
    warn(CFD_LOG_SOURCE, "unknown error.");
    throw CfdException();
  }
}

static struct wally_map* CreateKeyPathMap(const std::vector<KeyData>& key_list) {
  struct wally_map* map_obj = nullptr;
  int ret = wally_map_init_alloc(key_list.size(), &map_obj);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_init_alloc NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt alloc map error.");
  }
  for (auto& key : key_list) {
    auto key_vec = key.GetPubkey().GetData().GetBytes();
    std::vector<uint8_t> fingerprint(4);
    if (key.GetFingerprint().GetDataSize() >= 4) {
      fingerprint = key.GetFingerprint().GetBytes();
    }
    auto path = key.GetChildNumArray();

    ret = wally_map_add_keypath_item(
        map_obj, key_vec.data(), key_vec.size(),
        fingerprint.data(), 4, path.data(), path.size());
    if (ret != WALLY_OK) {
      wally_map_free(map_obj);
      warn(CFD_LOG_SOURCE, "wally_map_add_keypath_item NG[{}]", ret);
      throw CfdException(kCfdMemoryFullError, "psbt add keypath error.");
    }
  }
  return map_obj;
}

bool ValidateUtxo(const Txid& txid, uint32_t vout, const Script& out_script, const Script& redeem_script, const std::vector<KeyData>& key_list) {
  bool has_check_script = false;
  bool is_witness = false;

  if (out_script.IsP2pkhScript() || out_script.IsP2wpkhScript()) {
    if (!redeem_script.IsEmpty()) {
      warn(CFD_LOG_SOURCE, "pubkey isn't use redeemScript. txid:{},{}",
          txid.GetHex(), vout);
      throw CfdException(kCfdIllegalArgumentError, "pubkey isn't use redeemScript.");
    }
    
    if (key_list.size() > 1) {
      warn(CFD_LOG_SOURCE, "set many key. using key is one.",
          txid.GetHex(), vout);
      throw CfdException(kCfdIllegalArgumentError, "set many key. using key is one.");
    } else if (key_list.size() == 1) {
      auto pubkey = key_list[0].GetPubkey();
      if (out_script.IsP2wpkhScript()) {
        is_witness = true;
        if (!ScriptUtil::CreateP2wpkhLockingScript(
            pubkey).Equals(out_script)) {
          warn(CFD_LOG_SOURCE, "unmatch pubkey. txid:{},{}",
              txid.GetHex(), vout);
          throw CfdException(kCfdIllegalArgumentError, "unmatch pubkey.");
        }
      } else {
        if (!ScriptUtil::CreateP2pkhLockingScript(
            pubkey).Equals(out_script)) {
          warn(CFD_LOG_SOURCE, "unmatch pubkey. txid:{},{}",
              txid.GetHex(), vout);
          throw CfdException(kCfdIllegalArgumentError, "unmatch pubkey.");
        }
      }
    }
  } else if (out_script.IsP2shScript()) {
    if (redeem_script.IsEmpty() || redeem_script.IsP2wpkhScript()) {
      if (redeem_script.IsP2wpkhScript()) {
        auto p2sh_wpkh_script = ScriptUtil::CreateP2shLockingScript(redeem_script);
        if (!p2sh_wpkh_script.Equals(out_script)) {
          warn(CFD_LOG_SOURCE, "unmatch scriptPubkey. txid:{},{}",
              txid.GetHex(), vout);
          throw CfdException(kCfdIllegalArgumentError, "unmatch scriptPubkey.");
        }
      }

      if (key_list.size() > 1) {
        warn(CFD_LOG_SOURCE, "set many key. using key is one.",
            txid.GetHex(), vout);
        throw CfdException(kCfdIllegalArgumentError, "set many key. using key is one.");
      } else if (key_list.size() == 1) {
        auto pubkey = key_list[0].GetPubkey();
        auto wpkh_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
        auto sh_script = ScriptUtil::CreateP2shLockingScript(wpkh_script);
        if (!sh_script.Equals(out_script)) {
          warn(CFD_LOG_SOURCE, "unmatch pubkey. txid:{},{}",
              txid.GetHex(), vout);
          throw CfdException(kCfdIllegalArgumentError, "unmatch pubkey.");
        }
      }
      is_witness = true;
    } else {
      Address p2sh_addr(NetType::kMainnet, redeem_script);
      Address p2wsh_addr(NetType::kMainnet, WitnessVersion::kVersion0, redeem_script);
      auto p2sh_wsh_script = ScriptUtil::CreateP2shLockingScript(
          p2wsh_addr.GetLockingScript());
      if (p2sh_addr.GetLockingScript().Equals(out_script)) {
        has_check_script = true;
      } else if (p2sh_wsh_script.Equals(out_script)) {
        has_check_script = true;
        is_witness = true;
      } else {
        warn(CFD_LOG_SOURCE, "unknown scriptPubkey. txid:{},{}",
            txid.GetHex(), vout);
        throw CfdException(kCfdIllegalArgumentError, "unknown scriptPubkey.");
      }
    }
  } else if (out_script.IsP2wshScript()) {
    Address addr(NetType::kMainnet, WitnessVersion::kVersion0, redeem_script);
    if (!addr.GetLockingScript().Equals(out_script)) {
      warn(CFD_LOG_SOURCE, "unmatch scriptPubkey. txid:{},{}",
          txid.GetHex(), vout);
      throw CfdException(kCfdIllegalArgumentError, "unmatch scriptPubkey.");
    }
    has_check_script = true;
    is_witness = true;
  } else {
    warn(CFD_LOG_SOURCE, "unknown scriptPubkey. txid:{},{}",
        txid.GetHex(), vout);
    throw CfdException(kCfdIllegalArgumentError, "unknown scriptPubkey.");
  }

  if (has_check_script) {
    uint32_t count = 0;
    std::vector<Pubkey> pubkeys;
    if (redeem_script.IsMultisigScript()) {
      pubkeys = ScriptUtil::ExtractPubkeysFromMultisigScript(redeem_script);
    } else {
      auto items = redeem_script.GetElementList();
      for (auto item : items) {
        if (item.IsBinary() && Pubkey::IsValid(item.GetBinaryData())) {
          pubkeys.emplace_back(item.GetBinaryData());
        }
      }
    }
    for (auto key : key_list) {
      auto cur_pubkey = key.GetPubkey();
      for (auto pubkey : pubkeys) {
        if (pubkey.Equals(cur_pubkey)) {
          ++count;
          break;
        }
      }
    }
    if (count != key_list.size()) {
      warn(CFD_LOG_SOURCE, "unmatch key count. [{}:{}]", count, key_list.size());
      throw CfdException(kCfdIllegalArgumentError, "psbt key valid error.");
    }
  }
  return is_witness;
}

void SetTxInScriptAndKeyList(struct wally_psbt_input* input, bool is_witness, const Script &redeem_script, const std::vector<KeyData>& key_list) {
  int ret;
  if (!redeem_script.IsEmpty()) {
    auto script_val = redeem_script.GetData().GetBytes();
    if (is_witness && (!redeem_script.IsP2wpkhScript())) {
      ret = wally_psbt_input_set_witness_script(input,
          script_val.data(), script_val.size());
      if (ret != WALLY_OK) {
        warn(CFD_LOG_SOURCE, "wally_psbt_input_set_witness_script NG[{}]", ret);
        throw CfdException(kCfdIllegalArgumentError, "psbt add witness script error.");
      }
      script_val = ScriptUtil::CreateP2wshLockingScript(redeem_script).GetData().GetBytes();
    }
    ret = wally_psbt_input_set_redeem_script(input,
        script_val.data(), script_val.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_redeem_script NG[{}]", ret);
      throw CfdException(kCfdIllegalArgumentError, "psbt add redeem script error.");
    }
  }

  if (!key_list.empty()) {
    struct wally_map* map_obj = CreateKeyPathMap(key_list);
    ret = wally_psbt_input_set_keypaths(input, map_obj);
    wally_map_free(map_obj);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_output_set_keypaths NG[{}]", ret);
      throw CfdException(kCfdIllegalArgumentError, "psbt add output keypaths error.");
    }
  }
}

// -----------------------------------------------------------------------------
// Psbt
// -----------------------------------------------------------------------------
Psbt::Psbt() : Psbt(WALLY_PSBT_HIGHEST_VERSION, 2, static_cast<uint32_t>(0)) {
  // do nothing
}

Psbt::Psbt(uint32_t psbt_version, uint32_t version, uint32_t lock_time) {
  struct wally_psbt *psbt_pointer = nullptr;
  int ret = wally_psbt_elements_init_alloc(
      psbt_version, 0, 0, 0, &psbt_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_elements_init_alloc NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt data generate error.");
  }

  struct wally_tx tx;
  memset(&tx, 0, sizeof(tx));
  tx.version = version;
  tx.locktime = lock_time;
  ret = wally_psbt_set_global_tx(psbt_pointer, &tx);
  if (ret != WALLY_OK) {
    wally_psbt_free(psbt_pointer);  // free
    warn(CFD_LOG_SOURCE, "wally_psbt_set_global_tx NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt set tx error.");
  }
  wally_psbt_pointer_ = psbt_pointer;
  base_tx_ = RebuildTransaction(wally_psbt_pointer_);
}

Psbt::Psbt(const std::string &base64) {
  struct wally_psbt *psbt_pointer = nullptr;
  int ret = wally_psbt_from_base64(base64.c_str(), &psbt_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_from_base64 NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt from base64 error.");
  }
  wally_psbt_pointer_ = psbt_pointer;
  base_tx_ = RebuildTransaction(wally_psbt_pointer_);
}

Psbt::Psbt(const ByteData &byte_data) {
  std::vector<uint8_t> bytes = byte_data.GetBytes();
  struct wally_psbt *psbt_pointer = nullptr;
  int ret = wally_psbt_from_bytes(bytes.data(), bytes.size(), &psbt_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_from_bytes NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt from bytes error.");
  }
  wally_psbt_pointer_ = psbt_pointer;
  base_tx_ = RebuildTransaction(wally_psbt_pointer_);
}

Psbt::Psbt(uint32_t psbt_version, const Transaction &transaction) {
  std::string tx_hex = transaction.GetHex();
  auto txin_list = transaction.GetTxInList();
  auto txout_list = transaction.GetTxOutList();
  struct wally_tx* tx = nullptr;
  int ret = wally_tx_from_hex(tx_hex.data(), 0, &tx);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_from_hex NG[{}]", ret);
    if (txin_list.empty() || txout_list.empty()) {
      // fall-through
    } else {
      throw CfdException(kCfdInternalError, "psbt tx from hex error.");
    }
  }

  struct wally_psbt *psbt_pointer = nullptr;
  ret = wally_psbt_elements_init_alloc(
      psbt_version, txin_list.size(),
      txout_list.size(), 0, &psbt_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_elements_init_alloc NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt data generate error.");
  }

  if (tx == nullptr) {
    ret = wally_tx_init_alloc(
      transaction.GetVersion(), transaction.GetLockTime(),
      txin_list.size(), txout_list.size(), &tx);
    if (ret != WALLY_OK) {
      wally_psbt_free(psbt_pointer);  // free
      warn(CFD_LOG_SOURCE, "wally_psbt_set_global_tx NG[{}]", ret);
      throw CfdException(kCfdInternalError, "psbt set tx error.");
    }

    for (auto txin : txin_list) {
      auto txid_val = txin.GetTxid().GetData().GetBytes();
      ret = wally_tx_add_raw_input(
        tx, txid_val.data(), txid_val.size(), txin.GetVout(),
        txin.GetSequence(), nullptr, 0, nullptr, 0);
      if (ret != WALLY_OK) {
        wally_tx_free(tx);
        wally_psbt_free(psbt_pointer);  // free
        warn(CFD_LOG_SOURCE, "wally_tx_add_raw_input NG[{}]", ret);
        throw CfdException(kCfdInternalError, "psbt set tx input error.");
      }
    }
    for (auto txout : txout_list) {
      auto script_val = txout.GetLockingScript().GetData().GetBytes();
      ret = wally_tx_add_raw_output(
          tx, static_cast<uint64_t>(txout.GetValue().GetSatoshiValue()),
          script_val.data(), script_val.size(), 0);
      if (ret != WALLY_OK) {
        wally_tx_free(tx);
        wally_psbt_free(psbt_pointer);  // free
        warn(CFD_LOG_SOURCE, "wally_tx_add_raw_output NG[{}]", ret);
        throw CfdException(kCfdInternalError, "psbt set tx output error.");
      }
    }
  }

  ret = wally_psbt_set_global_tx(psbt_pointer, tx);
  wally_tx_free(tx);
  if (ret != WALLY_OK) {
    wally_psbt_free(psbt_pointer);  // free
    warn(CFD_LOG_SOURCE, "wally_psbt_set_global_tx NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt set tx error.");
  }
  wally_psbt_pointer_ = psbt_pointer;
  base_tx_ = RebuildTransaction(wally_psbt_pointer_);
}

Psbt::Psbt(const Psbt &transaction) : Psbt(transaction.GetData()) {
  // copy constructor
}

Psbt &Psbt::operator=(const Psbt &transaction) & {
  std::vector<uint8_t> bytes = transaction.GetData().GetBytes();
  struct wally_psbt *psbt_pointer = nullptr;
  int ret = wally_psbt_from_bytes(bytes.data(), bytes.size(), &psbt_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_from_bytes NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt from bytes error.");
  }
  FreeWallyPsbtAddress(wally_psbt_pointer_);  // free
  wally_psbt_pointer_ = psbt_pointer;
  base_tx_ = RebuildTransaction(wally_psbt_pointer_);
  return *this;
}

void Psbt::FreeWallyPsbtAddress(const void *wally_psbt_pointer) {
  if (wally_psbt_pointer != nullptr) {
    struct wally_psbt *psbt_pointer = nullptr;
    // ignore const
    memcpy(&psbt_pointer, &wally_psbt_pointer, sizeof(void *));
    wally_psbt_free(psbt_pointer);
  }
}

Transaction Psbt::RebuildTransaction(const void* wally_psbt_pointer) {
  Transaction tx;
    if (wally_psbt_pointer != nullptr) {
    const struct wally_psbt *psbt_pointer;
    psbt_pointer = static_cast<const struct wally_psbt *>(wally_psbt_pointer);
    if (psbt_pointer->tx != nullptr) {
      tx = Transaction(ConvertTxDataFromWally(psbt_pointer->tx));
    }
  }
  return tx;
}

std::string Psbt::GetBase64() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  char *output = nullptr;
  int ret = wally_psbt_to_base64(psbt_pointer, 0, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_to_base64 NG[{}]", ret);
    throw CfdException(kCfdIllegalStateError, "psbt to base64 error.");
  }
  return WallyUtil::ConvertStringAndFree(output);
}

ByteData Psbt::GetData() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  size_t size = 0;

  std::vector<uint8_t> bytes(GetDataSize());
  int ret =
      wally_psbt_to_bytes(psbt_pointer, 0, bytes.data(), bytes.size(), &size);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_to_bytes NG[{}]", ret);
    throw CfdException(kCfdIllegalStateError, "psbt to bytes error.");
  }
  return ByteData(bytes.data(), static_cast<uint32_t>(size));
}

uint32_t Psbt::GetDataSize() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  size_t size = 0;

  int ret = wally_psbt_get_length(psbt_pointer, 0, &size);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_get_length NG[{}]", ret);
    throw CfdException(kCfdIllegalStateError, "psbt get length error.");
  }
  return static_cast<uint32_t>(size);
}

bool Psbt::IsFinalized() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  size_t data = 0;
  int ret = wally_psbt_is_finalized(psbt_pointer, &data);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_is_finalized NG[{}]", ret);
    throw CfdException(kCfdIllegalStateError, "psbt check finalized error.");
  }
  return (data == 1);
}

bool Psbt::IsFinalizedInput(uint32_t index) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  size_t data = 0;
  if (psbt_pointer == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  }

  if ((psbt_pointer->inputs == nullptr) ||
      ((psbt_pointer->num_inputs <= index))) {
    warn(CFD_LOG_SOURCE, "psbt input out-of-range.");
    throw CfdException(kCfdOutOfRangeError, "psbt input out-of-range.");
  }

  int ret = wally_psbt_input_is_finalized(&psbt_pointer->inputs[index], &data);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_is_finalized NG[{}]", ret);
    throw CfdException(
        kCfdIllegalStateError, "psbt input check finalized error.");
  }
  return (data == 1);
}

#if 0
// FIXME cfdに移動
void Psbt::FinalizeInput(uint32_t index) {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (psbt_pointer == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  } else if (psbt_pointer->num_inputs <= index) {
    warn(CFD_LOG_SOURCE, "psbt index out of range");
    throw CfdException(kCfdOutOfRangeError, "psbt index out of range.");
  }

  size_t is_finalized = 0;
  int ret = wally_psbt_input_is_finalized(
      &psbt_pointer->inputs[index], &is_finalized);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_input_is_finalized NG[{}]", ret);
    throw CfdException(
        kCfdIllegalStateError, "psbt input finalize check error.");
  } else if (is_finalized == 0) {
    // verify
    // set script
  }
}

void Psbt::FinalizeInputAll() {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if ((psbt_pointer == nullptr) || (psbt_pointer->tx == nullptr)) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  } else if (psbt_pointer->num_inputs == 0) {
    warn(CFD_LOG_SOURCE, "psbt unset input.");
    throw CfdException(kCfdIllegalStateError, "psbt unset input.");
  }

  size_t tx_input_num = psbt_pointer->tx->num_inputs;
  if (psbt_pointer->num_inputs != tx_input_num) {
    warn(CFD_LOG_SOURCE, "psbt unmatch input num.");
    throw CfdException(kCfdIllegalStateError, "psbt unmatch input num.");
  }

  for (size_t index=0; index<psbt_pointer->num_inputs; ++index) {
    FinalizeInput(static_cast<uint32_t>(index));
  }
}
#endif

void Psbt::Finalize() {
  if (!IsFinalized()) {
    struct wally_psbt *psbt_pointer;
    psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
    int ret = wally_psbt_finalize(psbt_pointer);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_finalize NG[{}]", ret);
      throw CfdException(kCfdIllegalStateError, "psbt finalize error.");
    }
  }
}

ByteData Psbt::Extract() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  struct wally_tx *tx = nullptr;
  int ret = wally_psbt_extract(psbt_pointer, &tx);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_extract NG[{}]", ret);
    throw CfdException(kCfdIllegalStateError, "psbt extract error.");
  }
  return ConvertTxDataFromWally(tx);
}

Transaction Psbt::ExtractTransaction() const { return Transaction(Extract()); }

void Psbt::Combine(const Psbt &transaction) {
  std::vector<uint8_t> bytes = transaction.GetData().GetBytes();
  struct wally_psbt *src_pointer = nullptr;
  int ret = wally_psbt_from_bytes(bytes.data(), bytes.size(), &src_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_from_bytes NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt from bytes error.");
  }

  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  ret = wally_psbt_combine(psbt_pointer, src_pointer);
  wally_psbt_free(src_pointer);  // free
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_combine NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt combine error.");
  }
}

void Psbt::Sign(const Privkey &privkey, bool has_grind_r) {
  std::vector<uint8_t> key = privkey.GetData().GetBytes();
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  int ret = wally_psbt_sign(
      psbt_pointer, key.data(), key.size(),
      (has_grind_r) ? EC_FLAG_GRIND_R : 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_sign NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt sign error.");
  }
}

void Psbt::Join(const Psbt& transaction, bool ignore_duplicate_error) {
  // FIXME 実装する。（もしくはcfdへ）
  // 重複していない情報を追加する。（TxInのみ。TxOutは検知不能→前方一致で探索していって、異なるOutputがあれば追加という方針にする）
  // 重複は想定外のためエラーにするべきか？
  // 個人的には重複エラー無視のオプション指定つけたい。
}

uint32_t Psbt::AddTxIn(const TxIn &txin) {
  return AddTxIn(txin.GetTxid(), txin.GetVout(), txin.GetSequence());
}

uint32_t Psbt::AddTxIn(const TxInReference &txin) {
  return AddTxIn(txin.GetTxid(), txin.GetVout(), txin.GetSequence());
}

uint32_t Psbt::AddTxIn(const Txid &txid, uint32_t vout, uint32_t sequence) {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  uint32_t index = psbt_pointer->num_inputs;
  struct wally_tx_input *input = nullptr;
  std::vector<uint8_t> txhash = txid.GetData().GetBytes();

  int ret = wally_tx_input_init_alloc(txhash.data(), txhash.size(),
      vout, sequence, nullptr, 0, nullptr, &input);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_input_init_alloc NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt alloc input error.");
  }

  ret = wally_psbt_add_input_at(
    psbt_pointer, index, WALLY_PSBT_FLAG_NON_FINAL, input);
  wally_tx_input_free(input);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_add_input_at NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt add input error.");
  }
  return index;
}

void Psbt::SetTxInUtxo(uint32_t index, const Transaction& tx,
    const KeyData& key) {
  std::vector<KeyData> list(1);
  list[0] = key;
  SetTxInUtxo(index, tx, Script(), list);
}

void Psbt::SetTxInUtxo(uint32_t index, const Transaction& tx,
    const Script &redeem_script, const KeyData& key) {
  std::vector<KeyData> list(1);
  list[0] = key;
  SetTxInUtxo(index, tx, redeem_script, list);
}

void Psbt::SetTxInUtxo(uint32_t index, const Transaction& tx, const Script &redeem_script, const std::vector<KeyData>& key_list) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  uint8_t* txhash = psbt_pointer->tx->inputs[index].txhash;
  uint32_t vout = psbt_pointer->tx->inputs[index].index;
  auto txid = tx.GetTxid();
  auto tx_txid = txid.GetData().GetBytes();
  if ((memcmp(txhash, tx_txid.data(), tx_txid.size()) != 0) || (vout >= tx.GetTxOutCount())) {
    warn(CFD_LOG_SOURCE, "unmatch outpoint.");
    throw CfdException(kCfdIllegalArgumentError, "unmatch outpoint.");
  }

  auto txout = tx.GetTxOut(vout);
  bool is_witness = ValidateUtxo(txid, vout, txout.GetLockingScript(), redeem_script, key_list);

  struct wally_tx* wally_tx_obj = nullptr;
  int ret = wally_tx_from_hex(tx.GetHex().c_str(), 0, &wally_tx_obj);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_from_hex NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt tx from hex error.");
  }

  ret = wally_psbt_input_set_utxo(&psbt_pointer->inputs[index], wally_tx_obj);
  if (ret != WALLY_OK) {
    wally_tx_free(wally_tx_obj);
    warn(CFD_LOG_SOURCE, "wally_psbt_input_set_utxo NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt add utxo error.");
  }
  if (is_witness) {
    ret = wally_psbt_input_set_witness_utxo(&psbt_pointer->inputs[index],
        &wally_tx_obj->outputs[vout]);
    if (ret != WALLY_OK) {
      wally_tx_free(wally_tx_obj);
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_witness_utxo NG[{}]", ret);
      throw CfdException(kCfdIllegalArgumentError, "psbt add witness utxo error.");
    }
  }
  wally_tx_free(wally_tx_obj);

  SetTxInScriptAndKeyList(&psbt_pointer->inputs[index],
      is_witness, redeem_script, key_list);
}

void Psbt::SetTxInUtxo(uint32_t index, const TxOutReference& txout, const KeyData& key) {
  std::vector<KeyData> list(1);
  list[0] = key;
  SetTxInUtxo(index, txout, Script(), list);
}

void Psbt::SetTxInUtxo(uint32_t index, const TxOutReference& txout, const Script &redeem_script, const KeyData& key) {
  std::vector<KeyData> list(1);
  list[0] = key;
  SetTxInUtxo(index, txout, redeem_script, list);
}

void Psbt::SetTxInUtxo(uint32_t index, const TxOutReference& txout, const Script &redeem_script, const std::vector<KeyData>& key_list) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  uint8_t* txhash = psbt_pointer->tx->inputs[index].txhash;
  uint32_t vout = psbt_pointer->tx->inputs[index].index;
  Txid txid(ByteData256(ByteData(txhash,
    sizeof(psbt_pointer->tx->inputs[index].txhash))));

  auto script = txout.GetLockingScript();
  bool is_witness = ValidateUtxo(txid, vout, script, redeem_script, key_list);
  if (!is_witness) {
    warn(CFD_LOG_SOURCE, "non witness output is not supported.");
    throw CfdException(kCfdIllegalArgumentError, "psbt utxo type error.");
  }

  struct wally_tx_output *output = nullptr;
  auto script_val = script.GetData().GetBytes();
  int ret = wally_tx_output_init_alloc(
      static_cast<uint64_t>(txout.GetValue().GetSatoshiValue()),
      script_val.data(), script_val.size(), &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_output_init_alloc NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt alloc output error.");
  }

  ret = wally_psbt_input_set_witness_utxo(&psbt_pointer->inputs[index], output);
  wally_tx_output_free(output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_input_set_witness_utxo NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt add witness utxo error.");
  }

  SetTxInScriptAndKeyList(&psbt_pointer->inputs[index],
      is_witness, redeem_script, key_list);
}

void Psbt::SetTxInSignature(uint32_t index, const KeyData& key, const ByteData& signature) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto pubkey = key.GetPubkey().GetData().GetBytes();
  auto sig = signature.GetBytes();

  int ret = wally_psbt_input_add_signature(
    &psbt_pointer->inputs[index], pubkey.data(), pubkey.size(),
    sig.data(), sig.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_input_add_signature NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt add input sig error.");
  }
}

void Psbt::SetTxInSighashType(uint32_t index, const SigHashType& sighash_type) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  uint32_t sighash = sighash_type.GetSigHashFlag();

  int ret = wally_psbt_input_set_sighash(
    &psbt_pointer->inputs[index], sighash);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_input_set_sighash NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt set input sighash error.");
  }
}

void Psbt::SetTxInFinalScript(uint32_t index, const std::vector<ByteData>& unlocking_script) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (unlocking_script.empty()) {
    warn(CFD_LOG_SOURCE, "unlocking script is empty.");
    throw CfdException(kCfdIllegalArgumentError, "psbt unlocking script is empty.");
  }
  bool is_witness = false;
  auto redeem_script = GetTxInRedeemScript(index, true);

  auto utxo = GetTxInUtxo(index, true, &is_witness);
  bool is_wsh = false;
  int ret;
  if (is_witness) {
    auto last_stack = unlocking_script.back();
    if (redeem_script.GetData().Equals(last_stack)) {
      is_wsh = true;
    } else if (Pubkey::IsValid(last_stack)) {
      // p2wpkh
    } else {
      warn(CFD_LOG_SOURCE, "invalid unlocking_script.");
      throw CfdException(kCfdIllegalArgumentError, "psbt invalid unlocking_script error.");
    }

    struct wally_tx_witness_stack* stacks = nullptr;
    ret = wally_tx_witness_stack_init_alloc(unlocking_script.size(), &stacks);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_tx_witness_stack_init_alloc NG[{}]", ret);
      throw CfdException(kCfdIllegalArgumentError, "psbt init witness stack error.");
    }
    for (auto script : unlocking_script) {
      auto script_val = script.GetBytes();
      ret = wally_tx_witness_stack_add(stacks, script_val.data(), script_val.size());
      if (ret != WALLY_OK) {
        wally_tx_witness_stack_free(stacks);
        warn(CFD_LOG_SOURCE, "wally_tx_witness_stack_add NG[{}]", ret);
        throw CfdException(kCfdIllegalArgumentError, "psbt add witness stack error.");
      }
    }

    ret = wally_psbt_input_set_final_witness(&psbt_pointer->inputs[index], stacks);
    wally_tx_witness_stack_free(stacks);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_final_witness NG[{}]", ret);
      throw CfdException(kCfdIllegalArgumentError, "psbt set witness script error.");
    }
  } else {
    Script script_sig;
    if (unlocking_script.size() == 1) {
      script_sig = Script(unlocking_script[0]);
    } else {
      ScriptBuilder build;
      for (auto script : unlocking_script) {
        auto script_val = script.GetBytes();
        if (script_val.size() == 1) {
          build.AppendOperator(static_cast<ScriptType>(script_val[0]));
        } else {
          build.AppendData(script);
        }
      }
      script_sig = build.Build();
    }
    auto sig_val = script_sig.GetData().GetBytes();
    ret = wally_psbt_input_set_final_scriptsig(&psbt_pointer->inputs[index],
        sig_val.data(), sig_val.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_final_scriptsig NG[{}]", ret);
      throw CfdException(kCfdIllegalArgumentError, "psbt set scriptsig error.");
    }
  }

  if (is_witness && utxo.GetLockingScript().IsP2shScript()) {
    Script locking_script;
    if (is_wsh) {
      locking_script = ScriptUtil::CreateP2wshLockingScript(redeem_script);
    } else if (redeem_script.IsEmpty()) {
      auto key = GetTxInKeyData(index, true);
      locking_script = ScriptUtil::CreateP2wpkhLockingScript(key.GetPubkey());
    } else {
      locking_script = redeem_script;  // p2wpkh locking script
    }
    auto p2sh_script = ScriptUtil::CreateP2shLockingScript(locking_script);
    auto sig_val = p2sh_script.GetData().GetBytes();
    ret = wally_psbt_input_set_final_scriptsig(&psbt_pointer->inputs[index],
        sig_val.data(), sig_val.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_final_scriptsig NG[{}]", ret);
      throw CfdException(kCfdIllegalArgumentError, "psbt set scriptsig error.");
    }
  }
}

void Psbt::SetTxInProprietary(uint32_t index, const ByteData& key, const ByteData& value) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  struct wally_map* map_obj = nullptr;
  int ret = wally_map_init_alloc(1, &map_obj);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_init_alloc NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt alloc map error.");
  }

  auto key_vec = key.GetBytes();
  auto val_vec = value.GetBytes();
  ret = wally_map_add(map_obj,
      key_vec.data(), key_vec.size(), val_vec.data(), val_vec.size());
  if (ret != WALLY_OK) {
    wally_map_free(map_obj);
    warn(CFD_LOG_SOURCE, "wally_map_add NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt add map error.");
  }

  ret = wally_psbt_input_set_unknowns(&psbt_pointer->inputs[index], map_obj);
  wally_map_free(map_obj);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_input_set_unknowns NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt set unknown error.");
  }
}

Transaction Psbt::GetTxInUtxoFull(uint32_t index, bool ignore_error, bool* is_witness) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (psbt_pointer->inputs[index].utxo != nullptr) {
    if (is_witness != nullptr) {
      *is_witness = (psbt_pointer->inputs[index].witness_utxo != nullptr);
    }
    return Transaction(ConvertTxDataFromWally(
        psbt_pointer->inputs[index].utxo));
  } else if (ignore_error) {
    return Transaction();
  } else {
    warn(CFD_LOG_SOURCE, "utxo full data not found.");
    throw CfdException(kCfdIllegalStateError,
        "psbt utxo full data not found error.");
  }
}

TxOut Psbt::GetTxInUtxo(uint32_t index, bool ignore_error, bool* is_witness) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (psbt_pointer->inputs[index].witness_utxo != nullptr) {
    if (is_witness != nullptr) *is_witness = true;
    return TxOut(
      Amount(static_cast<int64_t>(
        psbt_pointer->inputs[index].witness_utxo->satoshi)),
      Script(ByteData(
        psbt_pointer->inputs[index].witness_utxo->script,
        psbt_pointer->inputs[index].witness_utxo->script_len)));
  } else if (psbt_pointer->inputs[index].utxo != nullptr) {
    if (is_witness != nullptr) {
      *is_witness = (psbt_pointer->inputs[index].witness_utxo != nullptr);
    }
    uint32_t vout = psbt_pointer->tx->inputs[index].index;
    return TxOut(
      Amount(static_cast<int64_t>(
        psbt_pointer->inputs[index].utxo->outputs[vout].satoshi)),
      Script(ByteData(
        psbt_pointer->inputs[index].utxo->outputs[vout].script,
        psbt_pointer->inputs[index].utxo->outputs[vout].script_len)));
  } else if (ignore_error) {
    return TxOut();
  } else {
    warn(CFD_LOG_SOURCE, "utxo not found.");
    throw CfdException(kCfdIllegalStateError, "psbt utxo not found error.");
  }
}

Script Psbt::GetTxInRedeemScript(uint32_t index, bool ignore_error, bool* is_witness) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (psbt_pointer->inputs[index].witness_script != nullptr) {
    if (is_witness != nullptr) *is_witness = true;
    return Script(ByteData(
        psbt_pointer->inputs[index].witness_script,
        psbt_pointer->inputs[index].witness_script_len));
  } else if (psbt_pointer->inputs[index].redeem_script != nullptr) {
    if (is_witness != nullptr) *is_witness = false;
    return Script(ByteData(
        psbt_pointer->inputs[index].redeem_script,
        psbt_pointer->inputs[index].redeem_script_len));
  } else if (ignore_error) {
    return Script();
  } else {
    warn(CFD_LOG_SOURCE, "script not found.");
    throw CfdException(kCfdIllegalStateError, "psbt script not found error.");
  }
}

std::vector<KeyData> Psbt::GetTxInKeyDataList(uint32_t index) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  size_t key_max = psbt_pointer->inputs[index].keypaths.num_items;
  std::vector<KeyData> arr;
  arr.reserve(key_max);
  struct wally_map_item *item;
  for (size_t key_index=0; key_index < key_max; ++key_index) {
    item = &psbt_pointer->inputs[index].keypaths.items[key_index];
    ByteData key(item->key, item->key_len);
    Pubkey pubkey(key);
    ByteData fingerprint;
    std::vector<uint32_t> path;
    if (((item->value_len % 4) == 0) && (item->value_len > 0)) {
      fingerprint = ByteData(item->value, 4);

      // TODO(k-matsuzawa) Need endian support.
      size_t arr_max = item->value_len / 4;
      uint32_t* val_arr = reinterpret_cast<uint32_t*>(item->value);
      for (size_t arr_index=1; arr_index < arr_max; ++arr_index) {
        path.push_back(val_arr[arr_index]);
      }
    }
    arr.emplace_back(KeyData(pubkey, path, fingerprint));
  }
  return arr;
}

KeyData Psbt::GetTxInKeyData(uint32_t index, bool ignore_error) const {
  std::vector<KeyData> keys = GetTxInKeyDataList(index);
  if (!keys.empty()) {
    return keys[0];
  } else if (ignore_error) {
    return KeyData();
  } else {
    warn(CFD_LOG_SOURCE, "key not found.");
    throw CfdException(kCfdIllegalStateError, "psbt key not found error.");
  }
}

std::vector<Pubkey> Psbt::GetTxInSignaturePubkeyList(uint32_t index) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  size_t key_max = psbt_pointer->inputs[index].signatures.num_items;
  std::vector<Pubkey> arr;
  arr.reserve(key_max);
  struct wally_map_item *item;
  for (size_t key_index=0; key_index < key_max; ++key_index) {
    item = &psbt_pointer->inputs[index].signatures.items[key_index];
    ByteData key(item->key, item->key_len);
    Pubkey pubkey(key);
    arr.emplace_back(pubkey);
  }
  return arr;
}

ByteData Psbt::GetTxInSignature(uint32_t index, const Pubkey& pubkey) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto key_vec = pubkey.GetData().GetBytes();
  size_t exist = 0;
  int ret = wally_map_find(&psbt_pointer->inputs[index].signatures,
      key_vec.data(), key_vec.size(), &exist);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_find NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt find signature key error.");
  }
  if (exist == 0) {
    warn(CFD_LOG_SOURCE, "target key not found.");
    throw CfdException(kCfdIllegalStateError,
        "psbt signature target key not found.");
  }
  uint32_t map_index = static_cast<uint32_t>(exist) - 1;
  return ByteData(
    psbt_pointer->unknowns.items[map_index].value,
    psbt_pointer->unknowns.items[map_index].value_len);
}

bool Psbt::IsFindTxInSignature(uint32_t index, const Pubkey& pubkey) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto key_vec = pubkey.GetData().GetBytes();
  size_t exist = 0;
  int ret = wally_map_find(&psbt_pointer->inputs[index].signatures,
      key_vec.data(), key_vec.size(), &exist);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_find NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt find signature key error.");
  }
  return (exist == 0) ? false : true;
}

SigHashType Psbt::GetTxInSighashType(uint32_t index) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (psbt_pointer->inputs[index].sighash != 0) {
    SigHashType sighash_type;
    sighash_type.SetFromSigHashFlag(static_cast<uint8_t>(
        psbt_pointer->inputs[index].sighash));
    return sighash_type;
  } else {
    warn(CFD_LOG_SOURCE, "sighash not found.");
    throw CfdException(kCfdIllegalStateError, "psbt sighash not found error.");
  }
}

bool Psbt::IsFindTxInSighashType(uint32_t index) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  return psbt_pointer->inputs[index].sighash != 0;
}

std::vector<ByteData> Psbt::GetTxInFinalScript(uint32_t index, bool is_witness_stack) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  std::vector<ByteData> result;

  if (is_witness_stack) {
    auto stacks = psbt_pointer->inputs[index].final_witness;
    for (size_t index=0; index<stacks->num_items; ++index) {
      result.emplace_back(
        stacks->items[index].witness,
        stacks->items[index].witness_len);
    }
  } else {
    result.emplace_back(
      psbt_pointer->inputs[index].final_scriptsig,
      psbt_pointer->inputs[index].final_scriptsig_len);
  }
  return result;
}

ByteData Psbt::GetTxInProprietary(uint32_t index, const ByteData& key) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto key_vec = key.GetBytes();
  size_t exist = 0;
  int ret = wally_map_find(&psbt_pointer->inputs[index].unknowns,
      key_vec.data(), key_vec.size(), &exist);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_find NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt find unknown key error.");
  }
  if (exist == 0) {
    warn(CFD_LOG_SOURCE, "target key not found.");
    throw CfdException(kCfdIllegalStateError,
        "psbt global target key not found.");
  }
  uint32_t map_index = static_cast<uint32_t>(exist) - 1;
  return ByteData(
    psbt_pointer->inputs[index].unknowns.items[map_index].value,
    psbt_pointer->inputs[index].unknowns.items[map_index].value_len);
}

bool Psbt::IsFindTxInProprietary(uint32_t index, const ByteData& key) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto key_vec = key.GetBytes();
  size_t exist = 0;
  int ret = wally_map_find(&psbt_pointer->inputs[index].unknowns,
      key_vec.data(), key_vec.size(), &exist);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_find NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt find unknown key error.");
  }
  return (exist == 0) ? false : true;
}

uint32_t Psbt::AddTxOut(const TxOut &txout) {
  return AddTxOut(txout.GetLockingScript(), txout.GetValue());
}

uint32_t Psbt::AddTxOut(const TxOutReference &txout) {
  return AddTxOut(txout.GetLockingScript(), txout.GetValue());
}

uint32_t Psbt::AddTxOut(const Script &locking_script, const Amount &amount) {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  uint32_t index = psbt_pointer->num_outputs;
  auto script = locking_script.GetData().GetBytes();
  struct wally_tx_output *output = nullptr;

  int ret = wally_tx_output_init_alloc(
      static_cast<uint64_t>(amount.GetSatoshiValue()),
      script.data(), script.size(), &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_output_init_alloc NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt alloc output error.");
  }

  ret = wally_psbt_add_output_at(psbt_pointer, index, 0, output);
  wally_tx_output_free(output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_add_output_at NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt add output error.");
  }
  return index;
}

void Psbt::SetTxOutData(uint32_t index, const KeyData& key) {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  std::vector<KeyData> arr = GetTxOutKeyDataList(index);
  Pubkey pubkey = key.GetPubkey();
  for (auto& item : arr) {
    if (pubkey.Equals(item.GetPubkey())) return;
  }

  struct wally_tx_output* txout = &psbt_pointer->tx->outputs[index];
  Script locking_script(ByteData(txout->script, txout->script_len));
  Script redeem_script;
  Script script;

  if (locking_script.IsP2pkhScript()) {
    script = ScriptUtil::CreateP2pkhLockingScript(pubkey);
  } else if (locking_script.IsP2wpkhScript()) {
    script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
  } else if (locking_script.IsP2shScript()) {
    auto wpkh_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
    script = ScriptUtil::CreateP2shLockingScript(wpkh_script);
    redeem_script = wpkh_script;
  }
  if (!locking_script.Equals(script)) {
    warn(CFD_LOG_SOURCE, "unmatch pubkey.");
    throw CfdException(kCfdIllegalArgumentError, "psbt unmatch pubkey error.");
  }

  if (!GetTxOutScript(index, true).IsEmpty()) redeem_script = Script();
  SetTxOutData(index, redeem_script, std::vector<KeyData>{key});
}

void Psbt::SetTxOutData(uint32_t index, const Script &redeem_script, const KeyData& key) {
  SetTxOutData(index, redeem_script, std::vector<KeyData>{key});
}

void Psbt::SetTxOutData(uint32_t index, const Script &redeem_script, const std::vector<KeyData>& key_list) {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  struct wally_tx_output* txout = &psbt_pointer->tx->outputs[index];
  Script script(ByteData(txout->script, txout->script_len));
  ByteData256 empty_bytes;
  Txid txid(empty_bytes);
  bool is_witness = ValidateUtxo(txid, index, script, redeem_script, key_list);

  int ret;
  if (!redeem_script.IsEmpty()) {
    auto script_val = redeem_script.GetData().GetBytes();
    if (is_witness && (!redeem_script.IsP2wpkhScript())) {
      ret = wally_psbt_output_set_witness_script(&psbt_pointer->outputs[index],
          script_val.data(), script_val.size());
      if (ret != WALLY_OK) {
        warn(CFD_LOG_SOURCE, "wally_psbt_output_set_witness_script NG[{}]", ret);
        throw CfdException(kCfdIllegalArgumentError, "psbt add output witness script error.");
      }
      script_val = ScriptUtil::CreateP2wshLockingScript(redeem_script).GetData().GetBytes();
    }
    ret = wally_psbt_output_set_redeem_script(&psbt_pointer->outputs[index],
        script_val.data(), script_val.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_output_set_redeem_script NG[{}]", ret);
      throw CfdException(kCfdIllegalArgumentError, "psbt add output redeem script error.");
    }
  }

  if (!key_list.empty()) {
    struct wally_map* map_obj = CreateKeyPathMap(key_list);
    ret = wally_psbt_output_set_keypaths(&psbt_pointer->outputs[index], map_obj);
    wally_map_free(map_obj);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_output_set_keypaths NG[{}]", ret);
      throw CfdException(kCfdIllegalArgumentError, "psbt add output keypaths error.");
    }
  }
}

void Psbt::SetTxOutProprietary(uint32_t index, const ByteData& key, const ByteData& value) {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  struct wally_map* map_obj = nullptr;
  int ret = wally_map_init_alloc(1, &map_obj);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_init_alloc NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt alloc map error.");
  }

  auto key_vec = key.GetBytes();
  auto val_vec = value.GetBytes();
  ret = wally_map_add(map_obj,
      key_vec.data(), key_vec.size(), val_vec.data(), val_vec.size());
  if (ret != WALLY_OK) {
    wally_map_free(map_obj);
    warn(CFD_LOG_SOURCE, "wally_map_add NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt add map error.");
  }

  ret = wally_psbt_output_set_unknowns(&psbt_pointer->outputs[index], map_obj);
  wally_map_free(map_obj);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_output_set_unknowns NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt set unknown error.");
  }
}

Script Psbt::GetTxOutScript(uint32_t index, bool ignore_error, bool* is_witness) const {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (psbt_pointer->outputs[index].witness_script != nullptr) {
    if (is_witness != nullptr) *is_witness = true;
    return Script(ByteData(
        psbt_pointer->outputs[index].witness_script,
        psbt_pointer->outputs[index].witness_script_len));
  } else if (psbt_pointer->outputs[index].redeem_script != nullptr) {
    if (is_witness != nullptr) *is_witness = false;
    return Script(ByteData(
        psbt_pointer->outputs[index].redeem_script,
        psbt_pointer->outputs[index].redeem_script_len));
  } else if (ignore_error) {
    return Script();
  } else {
    warn(CFD_LOG_SOURCE, "script not found.");
    throw CfdException(kCfdIllegalStateError, "psbt script not found error.");
  }
}

KeyData Psbt::GetTxOutKeyData(uint32_t index, bool ignore_error) const {
  auto arr = GetTxOutKeyDataList(index);
  if (arr.size() > 0) {
    return arr[0];
  } else if (ignore_error) {
    return KeyData();
  } else {
    warn(CFD_LOG_SOURCE, "key not found.");
    throw CfdException(kCfdIllegalStateError, "psbt key not found error.");
  }
}

std::vector<KeyData> Psbt::GetTxOutKeyDataList(uint32_t index) const {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  size_t key_max = psbt_pointer->outputs[index].keypaths.num_items;
  std::vector<KeyData> arr;
  arr.reserve(key_max);
  struct wally_map_item *item;
  for (size_t key_index=0; key_index < key_max; ++key_index) {
    item = &psbt_pointer->outputs[index].keypaths.items[key_index];
    ByteData key(item->key, item->key_len);
    Pubkey pubkey(key);
    ByteData fingerprint;
    std::vector<uint32_t> path;
    if (((item->value_len % 4) == 0) && (item->value_len > 0)) {
      fingerprint = ByteData(item->value, 4);

      // TODO(k-matsuzawa) Need endian support.
      size_t arr_max = item->value_len / 4;
      uint32_t* val_arr = reinterpret_cast<uint32_t*>(item->value);
      for (size_t arr_index=1; arr_index < arr_max; ++arr_index) {
        path.push_back(val_arr[arr_index]);
      }
    }
    arr.emplace_back(KeyData(pubkey, path, fingerprint));
  }
  return arr;
}

ByteData Psbt::GetTxOutProprietary(uint32_t index, const ByteData& key) const {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto key_vec = key.GetBytes();
  size_t exist = 0;
  int ret = wally_map_find(&psbt_pointer->outputs[index].unknowns,
      key_vec.data(), key_vec.size(), &exist);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_find NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt find unknown key error.");
  }
  if (exist == 0) {
    warn(CFD_LOG_SOURCE, "target key not found.");
    throw CfdException(kCfdIllegalStateError,
        "psbt global target key not found.");
  }
  uint32_t map_index = static_cast<uint32_t>(exist) - 1;
  return ByteData(
    psbt_pointer->outputs[index].unknowns.items[map_index].value,
    psbt_pointer->outputs[index].unknowns.items[map_index].value_len);
}

bool Psbt::IsFindTxOutProprietary(uint32_t index, const ByteData& key) const {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto key_vec = key.GetBytes();
  size_t exist = 0;
  int ret = wally_map_find(&psbt_pointer->outputs[index].unknowns,
      key_vec.data(), key_vec.size(), &exist);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_find NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt find unknown key error.");
  }
  return (exist == 0) ? false : true;
}

void Psbt::SetGlobalProprietary(const ByteData& key, const ByteData& value) {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto key_vec = key.GetBytes();
  auto val_vec = value.GetBytes();
  int ret = wally_map_add(&psbt_pointer->unknowns,
    key_vec.data(), key_vec.size(), val_vec.data(), val_vec.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_add NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt add unknown map error.");
  }
}

ByteData Psbt::GetGlobalProprietary(const ByteData& key) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto key_vec = key.GetBytes();
  size_t exist = 0;
  int ret = wally_map_find(
    &psbt_pointer->unknowns, key_vec.data(), key_vec.size(), &exist);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_find NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt find unknown key error.");
  }
  if (exist == 0) {
    warn(CFD_LOG_SOURCE, "target key not found.");
    throw CfdException(kCfdIllegalStateError,
        "psbt global target key not found.");
  }
  uint32_t map_index = static_cast<uint32_t>(exist) - 1;
  return ByteData(
    psbt_pointer->unknowns.items[map_index].value,
    psbt_pointer->unknowns.items[map_index].value_len);
}

bool Psbt::IsFindGlobalProprietary(const ByteData& key) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto key_vec = key.GetBytes();
  size_t exist = 0;
  int ret = wally_map_find(
    &psbt_pointer->unknowns, key_vec.data(), key_vec.size(), &exist);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_find NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt find unknown key error.");
  }
  return (exist == 0) ? false : true;
}

void Psbt::CheckTxInIndex(
    uint32_t index, int line, const char *caller) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (psbt_pointer == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  } else if (psbt_pointer->tx == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt base tx is null");
    throw CfdException(kCfdIllegalStateError, "psbt base tx is null.");
  } else if (psbt_pointer->num_inputs <= index) {
    spdlog::source_loc location = {CFD_LOG_FILE, line, caller};
    warn(location, "psbt vin[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "psbt vin out_of_range error.");
  } else if (psbt_pointer->tx->num_inputs <= index) {
    spdlog::source_loc location = {CFD_LOG_FILE, line, caller};
    warn(location, "tx vin[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "tx vin out_of_range error.");
  }
}

void Psbt::CheckTxOutIndex(
    uint32_t index, int line, const char *caller) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (psbt_pointer == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  } else if (psbt_pointer->tx == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt base tx is null");
    throw CfdException(kCfdIllegalStateError, "psbt base tx is null.");
  } else if (psbt_pointer->num_outputs <= index) {
    spdlog::source_loc location = {CFD_LOG_FILE, line, caller};
    warn(location, "psbt vout[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "psbt vout out_of_range error.");
  } else if (psbt_pointer->tx->num_outputs <= index) {
    spdlog::source_loc location = {CFD_LOG_FILE, line, caller};
    warn(location, "tx vout[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "tx vout out_of_range error.");
  }
}

}  // namespace core
}  // namespace cfd
