#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_taproot.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_block.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_descriptor.h"
#include "cfdcore/cfdcore_elements_transaction.h"

using cfd::core::BlockHash;
using cfd::core::TaprootScriptTree;
using cfd::core::TaprootUtil;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrPubkey;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptOperator;
using cfd::core::Script;
using cfd::core::ScriptBuilder;
using cfd::core::Transaction;
using cfd::core::Amount;
using cfd::core::Txid;
using cfd::core::TxIn;
using cfd::core::ScriptUtil;
using cfd::core::CryptoUtil;
using cfd::core::SigHashType;
using cfd::core::WitnessVersion;
using cfd::core::Address;
using cfd::core::TxOut;
using cfd::core::NetType;
using cfd::core::SchnorrUtil;
using cfd::core::SchnorrSignature;
using cfd::core::TapScriptData;
using cfd::core::TapBranch;
#ifndef CFD_DISABLE_ELEMENTS
using cfd::core::Descriptor;
using cfd::core::SigHashAlgorithm;
using cfd::core::ConfidentialTransaction;
using cfd::core::ConfidentialAssetId;
using cfd::core::ConfidentialValue;
using cfd::core::ConfidentialTxOut;
using cfd::core::GetElementsAddressFormatList;
#endif  // CFD_DISABLE_ELEMENTS

TEST(TaprootUtil, ValidLeafVersion) {
  EXPECT_FALSE(TaprootUtil::IsValidLeafVersion(0));
  EXPECT_TRUE(TaprootUtil::IsValidLeafVersion(0x66));
  EXPECT_TRUE(TaprootUtil::IsValidLeafVersion(0xc8));
  EXPECT_FALSE(TaprootUtil::IsValidLeafVersion(0xc9));
}

TEST(TaprootUtil, CreateTapScriptControl) {
  Privkey key("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  Script redeem_script = (ScriptBuilder() << schnorr_pubkey.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();
  std::vector<ByteData256> nodes = {
    ByteData256("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d"),
    ByteData256("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54")
  };
  TaprootScriptTree tree(redeem_script);
  tree.AddBranch(nodes[0]);
  tree.AddBranch(SchnorrPubkey(nodes[1]));
  // auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  // Script locking_script = ScriptUtil::CreateTaprootLockingScript(
  //   pk.GetByteData256());
  Script locking_script;
  SchnorrPubkey pk0;
  auto taproot_control = TaprootUtil::CreateTapScriptControl(
      schnorr_pubkey, tree, &pk0, &locking_script);
  Address addr01(NetType::kRegtest, WitnessVersion::kVersion1, pk0);
  EXPECT_EQ("bcrt1p8hh955u8526hjqhn5m5a5pmhymgecmxgerrmqj70tgvhk25mq8fq50z666", addr01.GetAddress());
  EXPECT_EQ(locking_script.GetHex(), addr01.GetLockingScript().GetHex());
  EXPECT_EQ("51203dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2", addr01.GetLockingScript().GetHex());

  Transaction tx1(2, 0);
  tx1.AddTxIn(
      Txid("cd6adc252632eb0768ac6407e586cc74bfed739d6c8b9efa55305eb37cbd76dd"),
      0, 0xffffffff);  // bcrt1qze8fshg0eykfy7nxcr96778xagufv2w429wx40
  Amount amt1(int64_t{2499999000});
  tx1.AddTxOut(amt1, locking_script);
  EXPECT_EQ("0200000001dd76bd7cb35e3055fa9e8b6c9d73edbf74cc86e50764ac6807eb322625dc6acd0000000000ffffffff0118f50295000000002251203dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d200000000", tx1.GetHex());
  Privkey key1 = Privkey::FromWif("cNveTchXQTFjtsMmR7B7MZmebXnU69S7PmDfgrUX6KbT9kyDLH57");
  Pubkey pk1("023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c44");
  auto pkh_script1 = ScriptUtil::CreateP2pkhLockingScript(pk1);
  SigHashType sighash_type;
  auto sighash = tx1.GetSignatureHash(0, pkh_script1.GetData(),
        sighash_type, Amount(int64_t{2500000000}), WitnessVersion::kVersion0);
  auto sig = key1.CalculateEcSignature(sighash);
  auto der_sig = CryptoUtil::ConvertSignatureToDer(sig, sighash_type);
  tx1.AddScriptWitnessStack(0, der_sig);
  tx1.AddScriptWitnessStack(0, pk1.GetData());
  EXPECT_EQ("02000000000101dd76bd7cb35e3055fa9e8b6c9d73edbf74cc86e50764ac6807eb322625dc6acd0000000000ffffffff0118f50295000000002251203dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d20247304402201db912bc61dab1c6117b0aec2965ea1b2d1caa42a1372adc16c8cf673f1187d7022062667d8a976b197f7ba33299365eeb68c1e45fa2a255411672d89f7afab12cb20121023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c4400000000", tx1.GetHex());
  
  Transaction tx2(2, 0);
  tx2.AddTxIn(tx1.GetTxid(), 0, 0xffffffff);  // taproot
  Address addr2("bcrt1qze8fshg0eykfy7nxcr96778xagufv2w429wx40");
  tx2.AddTxOut(Amount(int64_t{2499998000}), addr2.GetLockingScript());
  std::vector<TxOut> utxo_list(1);
  utxo_list[0] = TxOut(amt1, locking_script);
  TapScriptData script_data;
  script_data.tap_leaf_hash = tree.GetTapLeafHash();
  auto sighash2 = tx2.GetSchnorrSignatureHash(0, sighash_type, utxo_list, &script_data);
  EXPECT_EQ("80e53eaee13048aee9c6c13fa5a8529aad7fe2c362bfc16f1e2affc71f591d36", sighash2.GetHex());
  auto sig2 = SchnorrUtil::Sign(sighash2, key);
  EXPECT_EQ("f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee9", sig2.GetHex());
  SchnorrSignature schnorr_sig(sig2);
  schnorr_sig.SetSigHashType(sighash_type);
  tx2.AddScriptWitnessStack(0, schnorr_sig.GetData(true));
  tx2.AddScriptWitnessStack(0, redeem_script.GetData());
  tx2.AddScriptWitnessStack(0, taproot_control);
  EXPECT_EQ("020000000001015b80a1af0e00c700bee9c8e4442bec933fcdc0c686dac2dc336caaaf186c5d190000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50341f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee90122201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac61c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d5400000000", tx2.GetHex());

  EXPECT_TRUE(schnorr_pubkey.Verify(schnorr_sig, sighash2));
}

#ifndef CFD_DISABLE_ELEMENTS
TEST(TaprootUtil, CreateTapScriptControl_Elements) {
  Privkey key("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  Script redeem_script = (ScriptBuilder() << schnorr_pubkey.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();
  std::vector<ByteData256> nodes = {
    ByteData256("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d"),
    ByteData256("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54")
  };
  NetType net_type = NetType::kElementsRegtest;
  TaprootScriptTree tree(redeem_script, net_type);
  tree.AddBranch(nodes[0]);
  tree.AddBranch(SchnorrPubkey(nodes[1]));
  // auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  // Script locking_script = ScriptUtil::CreateTaprootLockingScript(
  //   pk.GetByteData256());
  Script locking_script;
  SchnorrPubkey pk0;
  auto taproot_control = TaprootUtil::CreateTapScriptControl(
      schnorr_pubkey, tree, &pk0, &locking_script);
  Address addr01(net_type, WitnessVersion::kVersion1, pk0, GetElementsAddressFormatList());
  EXPECT_EQ("ert1pugx48kntvdtm5vlr967s5wahgeu0889zwxgle0zn6tk39fp00zwqt6xq6r", addr01.GetAddress());
  EXPECT_EQ(locking_script.GetHex(), addr01.GetLockingScript().GetHex());
  EXPECT_EQ("5120e20d53da6b6357ba33e32ebd0a3bb74678f39ca27191fcbc53d2ed12a42f789c", addr01.GetLockingScript().GetHex());

  ConfidentialTransaction tx1(2, 0);
  ConfidentialAssetId asset("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225");
  tx1.AddTxIn(
      Txid("cd6adc252632eb0768ac6407e586cc74bfed739d6c8b9efa55305eb37cbd76dd"),
      0, 0xffffffff);  // ert1qze8fshg0eykfy7nxcr96778xagufv2w4j3mct0
  Amount amt0(int64_t{2500000000});
  ConfidentialValue val0(amt0);
  Amount amt1(int64_t{2499999000});
  ConfidentialValue val1(amt1);
  tx1.AddTxOut(amt1, asset, locking_script);
  Amount fee1(int64_t{1000});
  tx1.AddTxOutFee(fee1, asset);
  EXPECT_EQ("020000000001dd76bd7cb35e3055fa9e8b6c9d73edbf74cc86e50764ac6807eb322625dc6acd0000000000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000009502f51800225120e20d53da6b6357ba33e32ebd0a3bb74678f39ca27191fcbc53d2ed12a42f789c0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000003e8000000000000", tx1.GetHex());
  Privkey key1 = Privkey::FromWif("cNveTchXQTFjtsMmR7B7MZmebXnU69S7PmDfgrUX6KbT9kyDLH57");
  Pubkey pk1("023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c44");
  auto pkh_script1 = ScriptUtil::CreateP2pkhLockingScript(pk1);
  SigHashType sighash_type;
  auto sighash = tx1.GetElementsSignatureHash(0, pkh_script1.GetData(),
        sighash_type, val0, WitnessVersion::kVersion0);
  auto sig = key1.CalculateEcSignature(sighash);
  auto der_sig = CryptoUtil::ConvertSignatureToDer(sig, sighash_type);
  tx1.AddScriptWitnessStack(0, der_sig);
  tx1.AddScriptWitnessStack(0, pk1.GetData());
  EXPECT_EQ("020000000101dd76bd7cb35e3055fa9e8b6c9d73edbf74cc86e50764ac6807eb322625dc6acd0000000000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000009502f51800225120e20d53da6b6357ba33e32ebd0a3bb74678f39ca27191fcbc53d2ed12a42f789c0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000003e800000000000000000247304402204846079d356c76f5c59312b911d4096777aa40c06ffd77dc6836f85b42c1816702201f0df4a850234c82b1fb9c068a96a620d2038419e100eec9b6cff3f377a786130121023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c440000000000", tx1.GetHex());
  
  BlockHash genesis_block_hash("cc2641af46f536fba45aab6016f63e12a80e4c98bbb2686dafb22b9451cfe338");
  ConfidentialTransaction tx2(2, 0);
  tx2.AddTxIn(tx1.GetTxid(), 0, 0xffffffff);  // taproot
  Address addr2("ert1qze8fshg0eykfy7nxcr96778xagufv2w4j3mct0", GetElementsAddressFormatList());
  Amount amt2(int64_t{2499998000});
  ConfidentialValue val2(amt2);
  tx2.AddTxOut(amt2, asset, addr2.GetLockingScript());
  Amount fee2(int64_t{1000});
  tx1.AddTxOutFee(fee2, asset);
  std::vector<ConfidentialTxOut> utxo_list(1);
  utxo_list[0] = ConfidentialTxOut(locking_script, asset, val1);
  TapScriptData script_data;
  script_data.tap_leaf_hash = tree.GetTapLeafHash();
  auto sighash2 = tx2.GetElementsSchnorrSignatureHash(
    0, sighash_type, genesis_block_hash, utxo_list, &script_data);
  EXPECT_EQ("10ea5c82c50a85cce83931825bf181c99638e3412e7a0e0f438a4b11485174e8", sighash2.GetHex());
  auto sig2 = SchnorrUtil::Sign(sighash2, key);
  EXPECT_EQ("b216f1a52cacdd604568997ad5165d2a58cda57448fa1f1b0672cc0e6ba10b2accbc70a90baec517ee3df635de652aeefb5c11ac3873c58bdd00ea24d9cd9e06", sig2.GetHex());
  SchnorrSignature schnorr_sig(sig2);
  schnorr_sig.SetSigHashType(sighash_type);
  tx2.AddScriptWitnessStack(0, schnorr_sig.GetData(true));
  tx2.AddScriptWitnessStack(0, redeem_script.GetData());
  tx2.AddScriptWitnessStack(0, taproot_control);
  EXPECT_EQ("0200000001019923e6194a15c93658fb458cd38a4fe5326e45298b6dcf9184a022e352bc1c4b0000000000ffffffff010125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000009502f13000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50000000000000341b216f1a52cacdd604568997ad5165d2a58cda57448fa1f1b0672cc0e6ba10b2accbc70a90baec517ee3df635de652aeefb5c11ac3873c58bdd00ea24d9cd9e060122201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac61c51777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54000000", tx2.GetHex());

  EXPECT_TRUE(schnorr_pubkey.Verify(schnorr_sig, sighash2));
}

TEST(TaprootUtil, CreateTapScriptControl_Elements_Sign) {
  Privkey key = Privkey::FromWif(
    "cQRxS6BoPsuT8nyHMCYAKsRVDSnLisMxw4gUTeMURKioMMxTMSPE");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("91d3bd3d62082de37a6881c908f23ba6c357a2ad380dcaa5c50296a972603e0e",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  Script redeem_script = (ScriptBuilder() << schnorr_pubkey.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();
  std::vector<ByteData256> nodes;
  NetType net_type = NetType::kElementsRegtest;
  TaprootScriptTree tree(redeem_script, net_type);
  EXPECT_EQ("tl(2091d3bd3d62082de37a6881c908f23ba6c357a2ad380dcaa5c50296a972603e0eac)", tree.ToString());
  EXPECT_EQ("28acef70865e49908679b8dd6c3751f82dc4099b1d3d37affa685e928adc43f0", tree.GetTapLeafHash().GetHex());
  EXPECT_EQ("28acef70865e49908679b8dd6c3751f82dc4099b1d3d37affa685e928adc43f0", tree.GetCurrentBranchHash().GetHex());
  EXPECT_EQ("bde9b8f2c003300925e314249fea0daade214bbd4ce68c46f8989efc98544495", tree.GetTweakedPubkey(schnorr_pubkey).GetHex());
  Script locking_script;
  SchnorrPubkey pk0;
  auto taproot_control = TaprootUtil::CreateTapScriptControl(
      schnorr_pubkey, tree, &pk0, &locking_script);
  EXPECT_EQ("bde9b8f2c003300925e314249fea0daade214bbd4ce68c46f8989efc98544495", pk0.GetHex());
  Address addr01(net_type, WitnessVersion::kVersion1, pk0, GetElementsAddressFormatList());
  EXPECT_EQ("ert1phh5m3ukqqvcqjf0rzsjfl6sd4t0zzjaafnngc3hcnz00exz5gj2s8a8rjz", addr01.GetAddress());
  EXPECT_EQ(locking_script.GetHex(), addr01.GetLockingScript().GetHex());
  EXPECT_EQ("5120bde9b8f2c003300925e314249fea0daade214bbd4ce68c46f8989efc98544495", addr01.GetLockingScript().GetHex());
  EXPECT_TRUE(tree.HasTapLeaf());
  EXPECT_TRUE(tree.IsElements());

  auto desc = Descriptor::ParseElements("tr(91d3bd3d62082de37a6881c908f23ba6c357a2ad380dcaa5c50296a972603e0e,pk(91d3bd3d62082de37a6881c908f23ba6c357a2ad380dcaa5c50296a972603e0e))");
  auto ref = desc.GetReference();
  auto addr = ref.GenerateAddress(NetType::kElementsRegtest);
  EXPECT_EQ("ert1phh5m3ukqqvcqjf0rzsjfl6sd4t0zzjaafnngc3hcnz00exz5gj2s8a8rjz", addr.GetAddress());
  EXPECT_EQ("5120bde9b8f2c003300925e314249fea0daade214bbd4ce68c46f8989efc98544495", ref.GetLockingScript().GetHex());
  EXPECT_EQ("91d3bd3d62082de37a6881c908f23ba6c357a2ad380dcaa5c50296a972603e0e", ref.GetKeyList()[0].GetSchnorrPubkey().GetHex());
  EXPECT_EQ(tree.ToString(), ref.GetScriptTree().ToString());
  EXPECT_TRUE(ref.GetScriptTree().IsElements());

  ConfidentialTransaction tx1("020000000102f746647f2fd02ecfd3f669184c1f45e12ab9296f763c2d650d3f9ed4f520b0290100000000fffffffff746647f2fd02ecfd3f669184c1f45e12ab9296f763c2d650d3f9ed4f520b0290200000000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000017d77c300016001423dc2db292ef54e171839e4a4391d8b45aefcd4b0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000007d000000000000000000140396f2b94c6a81151d07faa26d5f5d7c751b62b1aea59ad7ed9d17fea60ef17e8e2eab28b55796ec0d01b0565c4658b279381674dcce633ee1851125ac762c494000000000000000000");
  ConfidentialAssetId asset("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225");
  std::vector<ConfidentialTxOut> utxo_list(2);
  utxo_list[0] = ConfidentialTxOut(
    Script("512016f8551db6483d403e9bf3c0b74a5bbafaa20cf0e45ca7e4a35cae924f7a0514"),
    asset, ConfidentialValue(Amount(200000000)));
  utxo_list[1] = ConfidentialTxOut(
    Script("5120e247cebb9d05e3ce87133b3c6cfd15eed31b43f61fe3ceede12594e55966035b"),
    asset, ConfidentialValue(Amount(200000000)));
  BlockHash genesis_block_hash("cc2641af46f536fba45aab6016f63e12a80e4c98bbb2686dafb22b9451cfe338");
  SigHashType sighash_type = SigHashType(SigHashAlgorithm::kSigHashDefault);
  TapScriptData script_data;
  script_data.tap_leaf_hash = tree.GetTapLeafHash();
  script_data.code_separator_position = cfd::core::kDefaultCodeSeparatorPosition;
  auto sighash2 = tx1.GetElementsSchnorrSignatureHash(
    0, sighash_type, genesis_block_hash, utxo_list, &script_data);
  EXPECT_EQ("b69db4132ff6a8e675a8fac89c94652e6331f09115ef3dfcb269842d0adba2cb", sighash2.GetHex());
  auto sig2 = SchnorrUtil::Sign(sighash2, key);
  EXPECT_EQ("2bcdd44189367114e401447d1c8e6990564e808b498fafe3eadc48159e282a256e1bfdcbbe28f6e941747f67f5ef10fd0041cbdcb4b302a7da7ec6ba5a24df5a", sig2.GetHex());
  SchnorrSignature schnorr_sig(sig2);
  schnorr_sig.SetSigHashType(sighash_type);
  tx1.AddScriptWitnessStack(0, schnorr_sig.GetData(true));
  tx1.AddScriptWitnessStack(0, redeem_script.GetData());
  tx1.AddScriptWitnessStack(0, taproot_control);
  EXPECT_EQ("020000000102f746647f2fd02ecfd3f669184c1f45e12ab9296f763c2d650d3f9ed4f520b0290100000000fffffffff746647f2fd02ecfd3f669184c1f45e12ab9296f763c2d650d3f9ed4f520b0290200000000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000017d77c300016001423dc2db292ef54e171839e4a4391d8b45aefcd4b0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000007d000000000000000000440396f2b94c6a81151d07faa26d5f5d7c751b62b1aea59ad7ed9d17fea60ef17e8e2eab28b55796ec0d01b0565c4658b279381674dcce633ee1851125ac762c494402bcdd44189367114e401447d1c8e6990564e808b498fafe3eadc48159e282a256e1bfdcbbe28f6e941747f67f5ef10fd0041cbdcb4b302a7da7ec6ba5a24df5a222091d3bd3d62082de37a6881c908f23ba6c357a2ad380dcaa5c50296a972603e0eac21c491d3bd3d62082de37a6881c908f23ba6c357a2ad380dcaa5c50296a972603e0e000000000000000000", tx1.GetHex());

  EXPECT_TRUE(schnorr_pubkey.Verify(schnorr_sig, sighash2));
}
#endif  // CFD_DISABLE_ELEMENTS

TEST(TaprootUtil, CreateTapScriptControlParityBit) {
  Privkey key("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  ScriptBuilder builder;
  builder.AppendData(schnorr_pubkey.GetData());
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script redeem_script = builder.Build();
  std::vector<ByteData256> nodes = {
    ByteData256("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d"),
    ByteData256("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d57")
  };
  TaprootScriptTree tree(redeem_script);
  tree.AddBranch(nodes[0]);
  tree.AddBranch(SchnorrPubkey(nodes[1]));
  // auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  // Script locking_script = ScriptUtil::CreateTaprootLockingScript(
  //   pk.GetByteData256());
  Script locking_script;
  auto taproot_control = TaprootUtil::CreateTapScriptControl(
      schnorr_pubkey, tree, nullptr, &locking_script);

  Transaction tx1(2, 0);
  tx1.AddTxIn(
      Txid("fee03a31ddbe8f8af75f9ccea23d2d49c27538b1c183aa90c4e35529161a78df"),
      0, 0xffffffff);  // bcrt1qze8fshg0eykfy7nxcr96778xagufv2w429wx40
  Amount amt1(int64_t{2499999000});
  tx1.AddTxOut(amt1, locking_script);
  EXPECT_EQ("0200000001df781a162955e3c490aa83c1b13875c2492d3da2ce9c5ff78a8fbedd313ae0fe0000000000ffffffff0118f5029500000000225120262d16c95b41f6a90a360837b5e9c3e213334deacffaec0413f8b6e98ad4016500000000", tx1.GetHex());
  Privkey key1 = Privkey::FromWif("cNveTchXQTFjtsMmR7B7MZmebXnU69S7PmDfgrUX6KbT9kyDLH57");
  Pubkey pk1("023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c44");
  auto pkh_script1 = ScriptUtil::CreateP2pkhLockingScript(pk1);
  SigHashType sighash_type;
  auto sighash = tx1.GetSignatureHash(0, pkh_script1.GetData(),
        sighash_type, Amount(int64_t{2500000000}), WitnessVersion::kVersion0);
  auto sig = key1.CalculateEcSignature(sighash);
  auto der_sig = CryptoUtil::ConvertSignatureToDer(sig, sighash_type);
  tx1.AddScriptWitnessStack(0, der_sig);
  tx1.AddScriptWitnessStack(0, pk1.GetData());
  EXPECT_EQ("02000000000101df781a162955e3c490aa83c1b13875c2492d3da2ce9c5ff78a8fbedd313ae0fe0000000000ffffffff0118f5029500000000225120262d16c95b41f6a90a360837b5e9c3e213334deacffaec0413f8b6e98ad4016502473044022068e673ac6db21d612864f432c5cfb64f3652e37be27de412c62dd6127ad63ce1022028507107481ad4fe97da3402eeff0540b0cc1677f9a53e87a7facf07c2696e500121023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c4400000000", tx1.GetHex());
  
  Transaction tx2(2, 0);
  tx2.AddTxIn(tx1.GetTxid(), 0, 0xffffffff);  // taproot
  Address addr2("bcrt1qze8fshg0eykfy7nxcr96778xagufv2w429wx40");
  tx2.AddTxOut(Amount(int64_t{2499998000}), addr2.GetLockingScript());
  std::vector<TxOut> utxo_list(1);
  utxo_list[0] = TxOut(amt1, locking_script);
  TapScriptData script_data;
  script_data.tap_leaf_hash = tree.GetTapLeafHash();
  auto sighash2 = tx2.GetSchnorrSignatureHash(0, sighash_type, utxo_list, &script_data);
  EXPECT_EQ("194c654c0547d805c158711fcf96ed9bc4afbd48556a0632cd2b18ec94c3f773", sighash2.GetHex());
  auto sig2 = SchnorrUtil::Sign(sighash2, key);
  EXPECT_EQ("bf55a5d15cc7dd2b583f571db0d59be9b1838a81191ad0e057caf9670d1b7de599864d6bd5e68bd56bb6da4d44e1dfd2deec3a03792c066613c4f6560d4876e0", sig2.GetHex());
  SchnorrSignature schnorr_sig(sig2);
  schnorr_sig.SetSigHashType(sighash_type);
  tx2.AddScriptWitnessStack(0, schnorr_sig.GetData(true));
  tx2.AddScriptWitnessStack(0, redeem_script.GetData());
  tx2.AddScriptWitnessStack(0, taproot_control);
  EXPECT_EQ("020000000001010513391eb3cb6529b86485dbee924a070a7e556c084ed6f0ff338d7a80335c450000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50341bf55a5d15cc7dd2b583f571db0d59be9b1838a81191ad0e057caf9670d1b7de599864d6bd5e68bd56bb6da4d44e1dfd2deec3a03792c066613c4f6560d4876e00122201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac61c11777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d5700000000", tx2.GetHex());

  EXPECT_TRUE(schnorr_pubkey.Verify(schnorr_sig, sighash2));
}

TEST(TaprootUtil, ParseTaprootSignDataByPubkey) {
  Transaction tx2("0200000000010116d975e4c2cea30f72f4f5fe528f5a0727d9ea149892a50c030d44423088ea2f0000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d5014161f75636003a870b7a1685abae84eedf8c9527227ac70183c376f7b3a35b07ebcbea14749e58ce1a87565b035b2f3963baa5ae3ede95e89fd607ab7849f208720100000000");
  auto stack = tx2.GetTxIn(0).GetScriptWitness().GetWitness();
  SchnorrSignature sig;
  bool parity = false;
  uint8_t tapleaf_flag = 0;
  SchnorrPubkey pk;
  std::vector<ByteData256> nodes;
  Script tapscript;
  std::vector<ByteData> script_stack;
  ByteData annex;
  TaprootUtil::ParseTaprootSignData(stack, &sig, &parity, &tapleaf_flag,
      &pk, &nodes, &tapscript, &script_stack, &annex);
  EXPECT_EQ("61f75636003a870b7a1685abae84eedf8c9527227ac70183c376f7b3a35b07ebcbea14749e58ce1a87565b035b2f3963baa5ae3ede95e89fd607ab7849f2087201", sig.GetHex(true));
  EXPECT_FALSE(parity);
  EXPECT_EQ(0, tapleaf_flag);
  EXPECT_FALSE(pk.IsValid());
  EXPECT_TRUE(nodes.empty());
  EXPECT_TRUE(tapscript.IsEmpty());
  EXPECT_TRUE(script_stack.empty());
  EXPECT_TRUE(annex.IsEmpty());
}

TEST(TaprootUtil, ParseAndVerifyTapScript) {
  Transaction tx2("020000000001015b80a1af0e00c700bee9c8e4442bec933fcdc0c686dac2dc336caaaf186c5d190000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50341f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee90122201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac61c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d5400000000");
  auto stack = tx2.GetTxIn(0).GetScriptWitness().GetWitness();
  SchnorrSignature sig;
  bool parity = false;
  uint8_t tapleaf_flag = 0;
  SchnorrPubkey pk;
  std::vector<ByteData256> nodes;
  Script tapscript;
  std::vector<ByteData> script_stack;
  ByteData annex;
  TaprootUtil::ParseTaprootSignData(stack, &sig, &parity, &tapleaf_flag,
      &pk, &nodes, &tapscript, &script_stack, &annex);
  EXPECT_EQ("", sig.GetHex());
  EXPECT_FALSE(parity);
  uint8_t ver = TaprootScriptTree::kTapScriptLeafVersion;
  EXPECT_EQ(ver, tapleaf_flag);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb", pk.GetHex());
  EXPECT_EQ(2, nodes.size());
  if (nodes.size() == 2) {
    EXPECT_EQ("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d",
        nodes[0].GetHex());
    EXPECT_EQ("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54",
        nodes[1].GetHex());
  }
  EXPECT_EQ("201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac",
      tapscript.GetHex());
  EXPECT_EQ(1, script_stack.size());
  if (script_stack.size() == 1) {
    EXPECT_EQ(
        "f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee901",
        script_stack[0].GetHex());
  }
  EXPECT_TRUE(annex.IsEmpty());

  EXPECT_TRUE(TaprootUtil::VerifyTaprootCommitment(
      parity, tapleaf_flag,
      SchnorrPubkey("3dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2"),
      pk, nodes, tapscript));
}

TEST(TaprootUtil, ParseAndVerifyTapScriptParityBit) {
  Transaction tx2("020000000001010513391eb3cb6529b86485dbee924a070a7e556c084ed6f0ff338d7a80335c450000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50341bf55a5d15cc7dd2b583f571db0d59be9b1838a81191ad0e057caf9670d1b7de599864d6bd5e68bd56bb6da4d44e1dfd2deec3a03792c066613c4f6560d4876e00122201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac61c11777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d5700000000");
  auto stack = tx2.GetTxIn(0).GetScriptWitness().GetWitness();
  SchnorrSignature sig;
  bool parity = false;
  uint8_t tapleaf_flag = 0;
  SchnorrPubkey pk;
  std::vector<ByteData256> nodes;
  Script tapscript;
  std::vector<ByteData> script_stack;
  ByteData annex;
  TaprootUtil::ParseTaprootSignData(stack, &sig, &parity, &tapleaf_flag,
      &pk, &nodes, &tapscript, &script_stack, &annex);
  EXPECT_EQ("", sig.GetHex());
  EXPECT_TRUE(parity);
  uint8_t ver = TaprootScriptTree::kTapScriptLeafVersion;
  EXPECT_EQ(ver, tapleaf_flag);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb", pk.GetHex());
  EXPECT_EQ(2, nodes.size());
  if (nodes.size() == 2) {
    EXPECT_EQ("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d",
        nodes[0].GetHex());
    EXPECT_EQ("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d57",
        nodes[1].GetHex());
  }
  EXPECT_EQ("201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac",
      tapscript.GetHex());
  EXPECT_EQ(1, script_stack.size());
  if (script_stack.size() == 1) {
    EXPECT_EQ(
        "bf55a5d15cc7dd2b583f571db0d59be9b1838a81191ad0e057caf9670d1b7de599864d6bd5e68bd56bb6da4d44e1dfd2deec3a03792c066613c4f6560d4876e001",
        script_stack[0].GetHex());
  }
  EXPECT_TRUE(annex.IsEmpty());

  EXPECT_TRUE(TaprootUtil::VerifyTaprootCommitment(
      parity, tapleaf_flag,
      SchnorrPubkey("262d16c95b41f6a90a360837b5e9c3e213334deacffaec0413f8b6e98ad40165"),
      pk, nodes, tapscript));
}

TEST(TaprootUtil, Bip86_1) {
  // https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
  // Account 0, second receiving address = m/86'/0'/0'/0/1
  // xprv         = xprvA449goEeU9okyiF1LmKiDaTgeXvmh87DVyRd35VPbsSop8n8uALpbtrUhUXByPFKK7C2yuqrB1FrhiDkEMC4RGmA5KTwsE1aB5jRu9zHsuQ
  // xpub         = xpub6H3W6JmYJXN4CCKUSnriaiQRCZmG6aq4sCMDqTu1ACyngw7HShf59hAxYjXgKDuuHThVEUzdHrc3aXCr9kfvQvZPit5dnD3K9xVRBzjK3rX
  // internal_key = 83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145
  // output_key   = a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb
  // scriptPubKey = 5120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb
  // address      = bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh
  SchnorrPubkey pk("83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145");
  TapBranch branch;

  SchnorrPubkey output_key;
  Script locking_script;
  auto ctrl = TaprootUtil::CreateTapScriptControl(
    pk, branch, &output_key, &locking_script);
  EXPECT_EQ("a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
      output_key.GetHex());
  EXPECT_EQ("5120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
      locking_script.GetHex());
  EXPECT_EQ("c083dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
      ctrl.GetHex());
  
  // for elements
  TapBranch branch_elements(NetType::kElementsRegtest);
  ctrl = TaprootUtil::CreateTapScriptControl(
    pk, branch_elements, &output_key, &locking_script);
  EXPECT_EQ("c73ac1b7a518499b9642aed8cfa15d5401e5bd85ad760b937b69521c297722f0",
      output_key.GetHex());
  EXPECT_EQ("5120c73ac1b7a518499b9642aed8cfa15d5401e5bd85ad760b937b69521c297722f0",
      locking_script.GetHex());
  EXPECT_EQ("c583dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
      ctrl.GetHex());
}
