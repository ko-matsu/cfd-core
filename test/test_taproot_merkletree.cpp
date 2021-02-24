#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_taproot.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_bytedata.h"

using cfd::core::TaprootScriptTree;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrPubkey;
using cfd::core::ByteData256;
using cfd::core::Script;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptOperator;
using cfd::core::SchnorrUtil;

TEST(TaprootScriptTree, Empty) {
  Privkey key("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  TaprootScriptTree tree;
  uint8_t ver = TaprootScriptTree::kTapScriptLeafVersion;
  EXPECT_EQ(ver, tree.GetLeafVersion());
  EXPECT_EQ("83d956a5b36109f8f667aa9b366e8479942e32396455b5f43b6df917768e4d45",
      tree.GetTapLeafHash().GetHex());
  EXPECT_EQ("83d956a5b36109f8f667aa9b366e8479942e32396455b5f43b6df917768e4d45",
      tree.GetCurrentBranchHash().GetHex());
  EXPECT_EQ("350105043b07771830fe4e4bd1a694d6aba22eb6e7f953d530f49b581d816bec",
      tree.GetTweakedPubkey(schnorr_pubkey).GetHex());
  EXPECT_EQ("023534977a61f3167b576ee7e636a4041d6451a58f708da24fac8bbd2d9e6b25",
      tree.GetTweakedPrivkey(key).GetHex());

  ByteData256 msg("e5b11ddceab1e4fc49a8132ae589a39b07acf49cabb2b0fbf6104bc31da12c02");
  auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  auto sk = tree.GetTweakedPrivkey(key);
  auto sig = SchnorrUtil::Sign(msg, sk);
  EXPECT_TRUE(pk.Verify(sig, msg));
}

TEST(TaprootScriptTree, Branch) {
  Privkey key("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_TRUE);
  Script script = builder.Build();
  uint8_t leaf_version = 0xc4;
  std::vector<ByteData256> nodes = {
    ByteData256("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d"),
    ByteData256("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54")
  };
  TaprootScriptTree tree(leaf_version, script);
  tree.AddBranch(nodes[0]);
  tree.AddBranch(SchnorrPubkey(nodes[1]));

  EXPECT_EQ(leaf_version, tree.GetLeafVersion());
  EXPECT_EQ(script.GetHex(), tree.GetScript().GetHex());
  EXPECT_EQ(nodes.size(), tree.GetNodeList().size());
  if (nodes.size() == tree.GetNodeList().size()) {
    for (size_t index=0; index<nodes.size(); ++index) {
      EXPECT_EQ(nodes[index].GetHex(), tree.GetNodeList()[index].GetHex());
    }
  }
  EXPECT_EQ("b893df7b9b277874f3427de6af5a8d9b1ba5ba6be139557d7a1db9cc4a4e5dae",
      tree.GetTapLeafHash().GetHex());
  EXPECT_EQ("daf066945913caa54e4ccfe32f0ca769b6c06679191cc01b9d96664226a1ffb4",
      tree.GetCurrentBranchHash().GetHex());
  EXPECT_EQ("cbdec1ab4d09f48ada05aacd1507e89d60671e37c8b3f714b3f6f6fbd6c71a2a",
      tree.GetTweakedPubkey(schnorr_pubkey).GetHex());
  EXPECT_EQ("9d7a9466774edd50d61e404568ecd7690ec8b2a656bb30ae66858a28a8a776ab",
      tree.GetTweakedPrivkey(key).GetHex());

  TaprootScriptTree tree2(tree);
  EXPECT_EQ("9d7a9466774edd50d61e404568ecd7690ec8b2a656bb30ae66858a28a8a776ab",
      tree2.GetTweakedPrivkey(key).GetHex());

  ByteData256 msg("e5b11ddceab1e4fc49a8132ae589a39b07acf49cabb2b0fbf6104bc31da12c02");
  auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  auto sk = tree.GetTweakedPrivkey(key);
  auto sig = SchnorrUtil::Sign(msg, sk);
  EXPECT_TRUE(pk.Verify(sig, msg));

  auto tree_str = tree.ToString();
  EXPECT_EQ(
    "tap_br(tap_br(4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d,tapleaf(196,tapscript(51))),dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54)",
    tree_str);
}

TEST(TaprootScriptTree, Branch2) {
  Privkey key("dd43698cf5f96d33bf895c28d67b5ffbd736c2d4cef91e1f8ce0e38c31a709c8");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_TRUE);
  Script script = builder.Build();
  uint8_t leaf_version = 0xc4;
  std::vector<ByteData256> nodes = {
    ByteData256("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d"),
    ByteData256("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d57")
  };
  TaprootScriptTree tree(leaf_version, script);
  for (const auto& node : nodes) {
    tree.AddBranch(node);
  }

  EXPECT_EQ(leaf_version, tree.GetLeafVersion());
  EXPECT_EQ(script.GetHex(), tree.GetScript().GetHex());
  EXPECT_EQ(nodes.size(), tree.GetNodeList().size());
  if (nodes.size() == tree.GetNodeList().size()) {
    for (size_t index=0; index<nodes.size(); ++index) {
      EXPECT_EQ(nodes[index].GetHex(), tree.GetNodeList()[index].GetHex());
    }
  }
  bool parity = false;
  EXPECT_EQ("b893df7b9b277874f3427de6af5a8d9b1ba5ba6be139557d7a1db9cc4a4e5dae",
      tree.GetTapLeafHash().GetHex());
  EXPECT_EQ("dc650bb6e95f7ee50dfbddf68651f77cd78c68f8f6c0c64014e5ef7c829c3635",
      tree.GetCurrentBranchHash().GetHex());
  EXPECT_EQ("300af27b4b5d270ec1ccc147210af5904724ef72d3ead21c569564a1536d33a3",
      tree.GetTweakedPubkey(schnorr_pubkey).GetHex());
  EXPECT_EQ("7801a8819654c6c31f5a7cbd152f881a138e2adfc64da9dc1f78fbf80640f53a",
      tree.GetTweakedPrivkey(key, &parity).GetHex());
  EXPECT_TRUE(parity);

  ByteData256 msg("e5b11ddceab1e4fc49a8132ae589a39b07acf49cabb2b0fbf6104bc31da12c02");
  auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  auto sk = tree.GetTweakedPrivkey(key);
  auto sig = SchnorrUtil::Sign(msg, sk);
  EXPECT_TRUE(pk.Verify(sig, msg));
}

TEST(TaprootScriptTree, TreeTest1) {
  Privkey key("dd43698cf5f96d33bf895c28d67b5ffbd736c2d4cef91e1f8ce0e38c31a709c8");
  ByteData256 tweak1("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d");
  ByteData256 tweak2("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d57");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);
  SchnorrPubkey schnorr_pubkey2 = schnorr_pubkey.CreateTweakAdd(tweak1);
  SchnorrPubkey schnorr_pubkey3 = schnorr_pubkey.CreateTweakAdd(tweak2);

  ScriptBuilder builder;

  builder.AppendData(schnorr_pubkey.GetData());
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script script = builder.Build();
  TaprootScriptTree tree1(script);

  builder = ScriptBuilder();
  builder.AppendOperator(ScriptOperator::OP_TRUE);
  TaprootScriptTree tree2(builder.Build());

  // <pubkey_1> CHECKSIGVERIFY ... <pubkey_(n-1)> CHECKSIGVERIFY <pubkey_n> CHECKSIG
  builder = ScriptBuilder();
  builder.AppendData(schnorr_pubkey2.GetData());
  builder.AppendOperator(ScriptOperator::OP_CHECKSIGVERIFY);
  builder.AppendData(schnorr_pubkey3.GetData());
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  TaprootScriptTree tree3(builder.Build());

  auto exp_hash = "a625d1251a1100263fa9a77b81e9e6f46c2eb8d44b9f27b629875cc102efb0ec";
  auto exp_str = "tap_br(tap_br(tapleaf(192,tapscript(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac)),tapleaf(192,tapscript(51))),tapleaf(192,tapscript(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)))";
  TaprootScriptTree root = tree1;
  root.AddBranch(tree2);
  root.AddBranch(tree3);
  EXPECT_EQ(exp_hash, root.GetCurrentBranchHash().GetHex());
  EXPECT_EQ(exp_str, root.ToString());

  root = tree2;
  root.AddBranch(tree1);
  root.AddBranch(tree3);
  EXPECT_EQ(exp_hash, root.GetCurrentBranchHash().GetHex());
  EXPECT_EQ(exp_str, root.ToString());

  auto branch = tree2;
  branch.AddBranch(tree1);
  root = tree3;
  root.AddBranch(branch);
  EXPECT_EQ(exp_hash, root.GetCurrentBranchHash().GetHex());
  EXPECT_EQ(exp_str, root.ToString());

  // blind leaf
  root = tree3;
  root.AddBranch(branch.GetCurrentBranchHash());
  EXPECT_EQ(exp_hash, root.GetCurrentBranchHash().GetHex());
  EXPECT_EQ(
      "tap_br(af151388d3bfbebcdc87e4a0b4a97bbfa378f2e5a909eb38a6978cb2a71f39c4,tapleaf(192,tapscript(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)))",
      root.ToString());
}
