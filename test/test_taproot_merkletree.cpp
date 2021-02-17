#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_taproot.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_bytedata.h"

using cfd::core::TaprootMerkleTree;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrPubkey;
using cfd::core::ByteData256;
using cfd::core::Script;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptOperator;
using cfd::core::SchnorrUtil;

TEST(TaprootMerkleTree, Empty) {
  Privkey key("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  TaprootMerkleTree tree;
  EXPECT_EQ(TaprootMerkleTree::kTapScriptLeafVersion, tree.GetLeafVersion());
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

TEST(TaprootMerkleTree, Branch) {
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
  TaprootMerkleTree tree(leaf_version, script);
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

  TaprootMerkleTree tree2(tree);
  EXPECT_EQ("9d7a9466774edd50d61e404568ecd7690ec8b2a656bb30ae66858a28a8a776ab",
      tree2.GetTweakedPrivkey(key).GetHex());

  ByteData256 msg("e5b11ddceab1e4fc49a8132ae589a39b07acf49cabb2b0fbf6104bc31da12c02");
  auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  auto sk = tree.GetTweakedPrivkey(key);
  auto sig = SchnorrUtil::Sign(msg, sk);
  EXPECT_TRUE(pk.Verify(sig, msg));
}

TEST(TaprootMerkleTree, Branch2) {
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
  TaprootMerkleTree tree(leaf_version, script);
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
