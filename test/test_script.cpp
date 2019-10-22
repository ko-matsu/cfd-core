#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_exception.h"

// https://qiita.com/yohm/items/477bac065f4b772127c7

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfd::core::Script;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptOperator;
using cfd::core::ScriptHash;
using cfd::core::ScriptElement;
using cfd::core::ByteData;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::NetType;
using cfd::core::CfdException;

TEST(Script, Script) {
  size_t size = 0;
  Script script;
  EXPECT_STREQ(script.GetHex().c_str(), "");
  EXPECT_EQ(script.IsEmpty(), true);
  EXPECT_EQ(script.GetData().GetDataSize(), size);
  EXPECT_EQ(script.GetElementList().size(), size);
}

TEST(Script, Script_hex) {
  size_t size = 5;
  std::string hex("76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  Script script(hex);
  EXPECT_STREQ(script.GetHex().c_str(),
               "76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
}

TEST(Script, Script_hex_exception) {
  try {
    std::string hex("xxxx");
    Script script(hex);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "hex to byte convert error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, Script_bytedata) {
  size_t size = 5;
  ByteData bytedata("76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  Script script(bytedata);
  EXPECT_STREQ(script.GetHex().c_str(),
               "76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
}

TEST(Script, SetStackData_OP0) {
  // script作成
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(
      "96376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  Script script = builder.Build();

  // OP_0 <hash160(pubkey)>
  size_t size = 2;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_STREQ(
      script.GetHex().c_str(),
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  EXPECT_STREQ(
      script.ToString().c_str(),
      "0 96376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
}

TEST(Script, SetStackData_kUseScriptNum1) {
  // script作成
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_IF);
  builder.AppendData(
      "0211dcbf6768e8eff85d7b294776f046a5294a64158586cd2bc6da4b0740eacd2f");
  builder.AppendOperator(ScriptOperator::OP_ELSE);
  builder.AppendData(144);
  builder.AppendOperator(ScriptOperator::OP_CHECKSEQUENCEVERIFY);
  builder.AppendOperator(ScriptOperator::OP_DROP);
  builder.AppendData(
      "03f7cfe9da8101afb6a6894cac696c7e1ba74fba3ed4caab5eb66c7df4c9558621");
  builder.AppendOperator(ScriptOperator::OP_ENDIF);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script script = builder.Build();

  // OP_IF pubkeyA OP_ELSE delay OP_CHECKSEQUENCEVERIFY OP_DROP pubkeyB OP_ENDIF OP_CHECKSIG
  size_t size = 9;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_STREQ(
      script.ToString().c_str(),
      "OP_IF 0211dcbf6768e8eff85d7b294776f046a5294a64158586cd2bc6da4b0740eacd2f OP_ELSE 144 OP_CHECKSEQUENCEVERIFY OP_DROP 03f7cfe9da8101afb6a6894cac696c7e1ba74fba3ed4caab5eb66c7df4c9558621 OP_ENDIF OP_CHECKSIG");
}

TEST(Script, SetStackData_kUseScriptNum2) {
  // script作成
  ScriptBuilder builder;
  builder.AppendData(5);
  builder.AppendData(2);
  builder.AppendOperator(ScriptOperator::OP_ADD);
  builder.AppendData(7);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  Script script = builder.Build();

  // OP_5 OP_2 OP_ADD OP_7 OP_EQUALVERIFY
  size_t size = 5;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_STREQ(script.GetHex().c_str(), "5552935788");
  EXPECT_STREQ(script.ToString().c_str(), "5 2 OP_ADD 7 OP_EQUALVERIFY");
}

TEST(Script, SetStackData_kUseScriptNum3) {
  // script作成
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_SIZE);
  builder.AppendOperator(ScriptOperator::OP_TUCK);
  builder.AppendData(0x20);
  builder.AppendData(0x23);
  builder.AppendOperator(ScriptOperator::OP_WITHIN);
  builder.AppendOperator(ScriptOperator::OP_VERIFY);
  Script script = builder.Build();

  // OP_SIZE OP_TUCK 20 23 OP_WITHIN OP_VERIFY
  size_t size = 6;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_STREQ(script.GetHex().c_str(), "827d01200123a569");
  EXPECT_STREQ(script.ToString().c_str(),
               "OP_SIZE OP_TUCK 32 35 OP_WITHIN OP_VERIFY");
}

TEST(Script, SetStackData_kOpPushData1) {
  // script作成
  ScriptBuilder builder;
  std::vector<uint8_t> bytes(255, 1);
  builder.AppendData(ByteData(bytes));
  Script script = builder.Build();

  size_t size = 1;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_EQ(script.GetData().GetBytes()[0], 0x4c);
}

TEST(Script, SetStackData_kOpPushData2) {
  // script作成
  ScriptBuilder builder;
  std::vector<uint8_t> bytes(256, 1);
  builder.AppendData(ByteData(bytes));
  Script script = builder.Build();

  size_t size = 1;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_EQ(script.GetData().GetBytes()[0], 0x4d);
}

TEST(Script, SetStackData_kOpPushData4) {
  // script作成
  // Builderではサイズエラーになるので、bytedataを自作
  std::vector<uint8_t> bytes(65541, 1);
  bytes[0] = 0x4e;
  bytes[1] = 0x00;
  bytes[2] = 0x00;
  bytes[3] = 0x01;
  bytes[4] = 0x00;
  Script script(bytes);

  size_t size = 1;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_EQ(script.GetData().GetBytes()[0], 0x4e);
}

TEST(Script, SetStackData_kOpPushData1_error) {
  try {
    std::vector<uint8_t> bytes(2, 0xff);
    bytes[0] = 0x4c;
    Script script(bytes);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "OP_PUSHDATA1 is incorrect size.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, SetStackData_kOpPushData2_error) {
  try {
    std::vector<uint8_t> bytes(2, 0xff);
    bytes[0] = 0x4d;
    Script script(bytes);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "OP_PUSHDATA2 is incorrect size.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, SetStackData_kOpPushData4_error) {
  try {
    std::vector<uint8_t> bytes(2, 0xff);
    bytes[0] = 0x4e;
    Script script(bytes);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "OP_PUSHDATA4 is incorrect size.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, SetStackData_size_error) {
  try {
    std::vector<uint8_t> bytes(10, 0x1);
    bytes[0] = 0x4e;
    Script script(bytes);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "buffer is incorrect size.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, GetScript) {
  ScriptBuilder builder;
  std::vector<uint8_t> bytes(255, 1);
  builder.AppendData(ByteData(bytes));
  Script script = builder.Build();

  Script script2 = script.GetScript();
  EXPECT_STREQ(script.GetHex().c_str(), script2.GetHex().c_str());
  EXPECT_STREQ(script.ToString().c_str(), script2.ToString().c_str());
}

TEST(Script, GetScriptHash) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  ScriptHash script_hash = script.GetScriptHash();
  EXPECT_STREQ(script_hash.GetHex().c_str(),
               "a9145528d5065b3f370375a651128077eaf3258531d887");
}

TEST(Script, GetWitnessScriptHash) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  ScriptHash script_hash = script.GetWitnessScriptHash();
  EXPECT_STREQ(
      script_hash.GetHex().c_str(),
      "00206bb5cc76cdbd684cb6f7c43a98c61c5aa789368d5e319e6c8258de3fec796562");
}

TEST(Script, GetData) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  ByteData byte_data = script.GetData();
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
}

TEST(Script, GetHex) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  std::string hex = script.GetHex();
  EXPECT_STREQ(
      hex.c_str(),
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
}

TEST(Script, IsEmpty_true) {
  Script script;
  EXPECT_EQ(script.IsEmpty(), true);
}

TEST(Script, IsEmpty_false) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  EXPECT_EQ(script.IsEmpty(), false);
}

TEST(Script, GetElementList) {
  ScriptBuilder builder;
  builder.AppendData(5);
  builder.AppendData(2);
  builder.AppendOperator(ScriptOperator::OP_ADD);
  builder.AppendData(7);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  Script script = builder.Build();

  size_t size = 5;
  std::vector<ScriptElement> list = script.GetElementList();
  EXPECT_EQ(list.size(), size);
}

TEST(Script, ToString) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  EXPECT_STREQ(
      script.ToString().c_str(),
      "0 96376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
}

TEST(Script, ToString_empty) {
  Script script;
  EXPECT_STREQ(script.ToString().c_str(), "");
}

TEST(Script, IsPushOnly_true) {
  ScriptBuilder builder;
  builder.AppendData(5);
  Script script = builder.Build();
  EXPECT_EQ(script.IsPushOnly(), true);
}

TEST(Script, IsPushOnly_false) {
  ScriptBuilder builder;
  builder.AppendData(5);
  builder.AppendData(2);
  builder.AppendOperator(ScriptOperator::OP_ADD);
  builder.AppendData(7);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  Script script = builder.Build();
  EXPECT_EQ(script.IsPushOnly(), false);
}

TEST(Script, IsPushOnly_empty) {
  Script script;
  EXPECT_EQ(script.IsPushOnly(), true);
}

TEST(Script, IsP2pkScriptTest) {
  ScriptBuilder builder;
  builder.AppendData(Pubkey("0288b03ce954e6eccfd9bdfd8cea71f80957e20d37d020b1b99973ea9f897f2b81"));
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script script = builder.Build();

  EXPECT_TRUE(script.IsP2pkScript());
  EXPECT_FALSE(script.IsP2pkhScript());
  EXPECT_FALSE(script.IsP2shScript());
  EXPECT_FALSE(script.IsMultisigScript());
  EXPECT_FALSE(script.IsWitnessProgram());
  EXPECT_FALSE(script.IsP2wpkhScript());
  EXPECT_FALSE(script.IsP2wshScript());
  EXPECT_FALSE(script.IsPegoutScript());
}

TEST(Script, IsP2pkhScriptTest) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(ByteData("18763afd24a108d323f53ebcea974e7f7d309503"));
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script script = builder.Build();

  EXPECT_FALSE(script.IsP2pkScript());
  EXPECT_TRUE(script.IsP2pkhScript());
  EXPECT_FALSE(script.IsP2shScript());
  EXPECT_FALSE(script.IsMultisigScript());
  EXPECT_FALSE(script.IsWitnessProgram());
  EXPECT_FALSE(script.IsP2wpkhScript());
  EXPECT_FALSE(script.IsP2wshScript());
  EXPECT_FALSE(script.IsPegoutScript());
}

TEST(Script, IsP2shScriptTest) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(ByteData("776f6d27bac2dabca92ac82d3ec353ec6f0550c4"));
  builder.AppendOperator(ScriptOperator::OP_EQUAL);
  Script script = builder.Build();

  EXPECT_FALSE(script.IsP2pkScript());
  EXPECT_FALSE(script.IsP2pkhScript());
  EXPECT_TRUE(script.IsP2shScript());
  EXPECT_FALSE(script.IsMultisigScript());
  EXPECT_FALSE(script.IsWitnessProgram());
  EXPECT_FALSE(script.IsP2wpkhScript());
  EXPECT_FALSE(script.IsP2wshScript());
  EXPECT_FALSE(script.IsPegoutScript());
}

TEST(Script, IsMultisigScriptTest) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_2);
  builder.AppendData(Pubkey("0288b03ce954e6eccfd9bdfd8cea71f80957e20d37d020b1b99973ea9f897f2b81"));
  builder.AppendData(Pubkey("03af2df16372b687457c4e522141ca5a600d64c61f3d7a19a465c051d060bdd727"));
  builder.AppendData(Pubkey("02582b60250c5f99ab33faaec09c047f68e81bc267e4da7f136dc7b72afdaf0183"));
  builder.AppendOperator(ScriptOperator::OP_3);
  builder.AppendOperator(ScriptOperator::OP_CHECKMULTISIG);
  Script script = builder.Build();

  EXPECT_FALSE(script.IsP2pkScript());
  EXPECT_FALSE(script.IsP2pkhScript());
  EXPECT_FALSE(script.IsP2shScript());
  EXPECT_TRUE(script.IsMultisigScript());
  EXPECT_FALSE(script.IsWitnessProgram());
  EXPECT_FALSE(script.IsP2wpkhScript());
  EXPECT_FALSE(script.IsP2wshScript());
  EXPECT_FALSE(script.IsPegoutScript());
}

TEST(Script, IsP2wpkhScriptTest) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(ByteData("18763afd24a108d323f53ebcea974e7f7d309503"));
  Script script = builder.Build();

  EXPECT_FALSE(script.IsP2pkScript());
  EXPECT_FALSE(script.IsP2pkhScript());
  EXPECT_FALSE(script.IsP2shScript());
  EXPECT_FALSE(script.IsMultisigScript());
  EXPECT_TRUE(script.IsWitnessProgram());
  EXPECT_TRUE(script.IsP2wpkhScript());
  EXPECT_FALSE(script.IsP2wshScript());
  EXPECT_FALSE(script.IsPegoutScript());
}

TEST(Script, IsP2wshScriptTest) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(ByteData("0225718cefb8c26fdc0343681d116f5bdf6d6cd9dcf6a28067c76c9385e89fe3"));
  Script script = builder.Build();

  EXPECT_FALSE(script.IsP2pkScript());
  EXPECT_FALSE(script.IsP2pkhScript());
  EXPECT_FALSE(script.IsP2shScript());
  EXPECT_FALSE(script.IsMultisigScript());
  EXPECT_TRUE(script.IsWitnessProgram());
  EXPECT_FALSE(script.IsP2wpkhScript());
  EXPECT_TRUE(script.IsP2wshScript());
  EXPECT_FALSE(script.IsPegoutScript());
}

TEST(Script, IsPegoutScriptTest) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_RETURN);
  builder.AppendData(ByteData("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"));
  builder.AppendData(ByteData("a91453c252a6a1379642adea35d055329ea04528eab787"));
  Script script = builder.Build();

  EXPECT_FALSE(script.IsP2pkScript());
  EXPECT_FALSE(script.IsP2pkhScript());
  EXPECT_FALSE(script.IsP2shScript());
  EXPECT_FALSE(script.IsMultisigScript());
  EXPECT_FALSE(script.IsWitnessProgram());
  EXPECT_FALSE(script.IsP2wpkhScript());
  EXPECT_FALSE(script.IsP2wshScript());
  EXPECT_TRUE(script.IsPegoutScript());
}


TEST(Script, ConvertFromMiniScriptTest) {
  cfd::core::CfdCoreHandle handle = nullptr;
  cfd::core::Initialize(&handle);

  std::string miniscript;
  Script script;
  try {
    miniscript = "and_v(vc:pk(K),c:pk(A))";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "030000000000000000000000000000000000000000000000000000000000000000 OP_CHECKSIG OP_CHECKSIGVERIFY 030000000000000000000000000000000000000000000000000000000000000000 OP_CHECKSIG");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {   // fail
    // multisig
    miniscript = "thresh_m(1,0306226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f,030000000000000000000000000000000000000000000000000000000000000001)";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {
    // miniscript - A single key
    miniscript = "c:pk(027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af)";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af OP_CHECKSIG");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {
    // miniscript - One of two keys (equally likely)
    // or_b(c:pk(key_1),sc:pk(key_2))
    miniscript = "or_b(c:pk(027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),sc:pk(036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af))";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af OP_CHECKSIG OP_SWAP 036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af OP_CHECKSIG OP_CHECKSIG OP_BOOLOR");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {   // fail
    // miniscript - One of two keys (one likely, one unlikely)
    // or_d(c:pk(key_likely),c:pk_h(key_unlikely))
    miniscript = "or_d(c:pk(027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),c:pk_h(925d4028880bd0c9d68fbc7fc7dfee976698629c))";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {   // テンプレートだと上手くいく。既存不具合。
    // miniscript - One of two keys (one likely, one unlikely)
    // or_d(c:pk(key_likely),c:pk_h(key_unlikely))
    miniscript = "or_d(c:pk(key_likely),c:pk_h(key_unlikely))";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "030000000000000000000000000000000000000000000000000000000000000000 OP_CHECKSIG OP_IFDUP OP_NOTIF OP_DUP OP_HASH160 030000000000000000000000000000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG OP_ENDIF");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {   // fail
    // miniscript - A 3-of-3 that turns into a 2-of-3 after 90 days
    // thresh(3,c:pk(key_1),sc:pk(key_2),sc:pk(key_3),sdv:older(12960))
    miniscript = "thresh(3,c:pk(027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),sc:pk(036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),sc:pk(0211dcbf6768e8eff85d7b294776f046a5294a64158586cd2bc6da4b0740eacd2f),sdv:older(12960))";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {   // fail
    // miniscript - A 3-of-3 that turns into a 2-of-3 after 90 days
    // thresh(3,c:pk(key_1),sc:pk(key_2),sc:pk(key_3),sdv:older(12960))
    miniscript = "thresh(3,c:pk(key_1),sc:pk(key_2),sc:pk(key_3),sdv:older(12960))";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {   // fail
    // miniscript - The BOLT #3 to_local policy
    // andor(c:pk(key_local),older(1008),c:pk(key_revocation))
    miniscript = "andor(c:pk(027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),older(1008),c:pk(036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af))";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {   // fail
    // miniscript - The BOLT #3 to_local policy
    // andor(c:pk(key_local),older(1008),c:pk(key_revocation))
    miniscript = "andor(c:pk(key_local),older(1008),c:pk(key_revocation))";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {   // fail
    // miniscript - A user and a 2FA service need to sign off, but after 90 days the user alone is enough
    // and_v(vc:pk(key_user),or_d(c:pk(key_service),older(12960)))
    miniscript = "and_v(vc:pk(027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),or_d(c:pk(036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),older(12960)))";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {   // fail
    // miniscript - A user and a 2FA service need to sign off, but after 90 days the user alone is enough
    // and_v(vc:pk(key_user),or_d(c:pk(key_service),older(12960)))
    miniscript = "and_v(vc:pk(key_user),or_d(c:pk(key_service),older(12960)))";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {   // fail
    // miniscript - The BOLT #3 offered HTLC policy
    miniscript = "t:or_c(c:pk(key_revocation),and_v(vc:pk(key_remote),or_c(c:pk(key_local),v:hash160(H))))";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }

  try {   // fail
    // miniscript - The BOLT #3 received HTLC policy
    miniscript = "andor(c:pk(key_remote),or_i(and_v(vc:pk_h(key_local),hash160(H)),older(1008)),c:pk(key_revocation))";
    script = Script::ConvertFromMiniScript(miniscript);
    EXPECT_STREQ(script.ToString().c_str(),
        "");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  } catch (...) {
    EXPECT_TRUE(false);
  }
}

TEST(Script, GetMiniScriptTest) {
  cfd::core::CfdCoreHandle handle = nullptr;
  cfd::core::Initialize(&handle);
  Script script;
  ScriptBuilder builder;
  std::string miniscript;
  try {
    // multisig
    builder = ScriptBuilder();
    builder.AppendOperator(ScriptOperator::OP_1);
    builder.AppendData(ByteData("0306226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"));
    builder.AppendData(ByteData("030000000000000000000000000000000000000000000000000000000000000001"));
    builder.AppendOperator(ScriptOperator::OP_2);
    builder.AppendOperator(ScriptOperator::OP_CHECKMULTISIG);
    script = builder.Build();
    miniscript = script.GetMiniScript();
    EXPECT_STREQ(miniscript.c_str(),
        "thresh_m(1,0306226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f,030000000000000000000000000000000000000000000000000000000000000001)");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  }

  try {
    // miniscript - A single key
    builder = ScriptBuilder();
    builder.AppendData(ByteData("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    script = builder.Build();
    miniscript = script.GetMiniScript();
    EXPECT_STREQ(miniscript.c_str(),
        "c:pk(027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af)");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  }

  try {
    // miniscript - One of two keys (equally likely)
    builder = ScriptBuilder();
    builder.AppendData(ByteData("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_SWAP);
    builder.AppendData(ByteData("036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_BOOLOR);
    script = builder.Build();
    miniscript = script.GetMiniScript();
    EXPECT_STREQ(miniscript.c_str(),
        "or_b(c:pk(027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),sc:pk(036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af))");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  }

  try {
    // miniscript - One of two keys (one likely, one unlikely)
    builder = ScriptBuilder();
    builder.AppendData(ByteData("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_IFDUP);
    builder.AppendOperator(ScriptOperator::OP_NOTIF);
    builder.AppendOperator(ScriptOperator::OP_DUP);
    builder.AppendOperator(ScriptOperator::OP_HASH160);
    builder.AppendData(ByteData("925d4028880bd0c9d68fbc7fc7dfee976698629c"));
    builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_ENDIF);
    script = builder.Build();
    miniscript = script.GetMiniScript();
    EXPECT_STREQ(miniscript.c_str(),
        "or_d(c:pk(027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),c:pk_h(925d4028880bd0c9d68fbc7fc7dfee976698629c))");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  }

  try {
    // miniscript - A 3-of-3 that turns into a 2-of-3 after 90 days
    builder = ScriptBuilder();
    builder.AppendData(ByteData("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_SWAP);
    builder.AppendData(ByteData("036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_ADD);
    builder.AppendOperator(ScriptOperator::OP_SWAP);
    builder.AppendData(ByteData("0211dcbf6768e8eff85d7b294776f046a5294a64158586cd2bc6da4b0740eacd2f"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_ADD);
    builder.AppendOperator(ScriptOperator::OP_SWAP);
    builder.AppendOperator(ScriptOperator::OP_DUP);
    builder.AppendOperator(ScriptOperator::OP_IF);
    builder.AppendData(12960);
    builder.AppendOperator(ScriptOperator::OP_CHECKSEQUENCEVERIFY);
    builder.AppendOperator(ScriptOperator::OP_VERIFY);
    builder.AppendOperator(ScriptOperator::OP_ENDIF);
    builder.AppendOperator(ScriptOperator::OP_ADD);
    builder.AppendData(3);
    builder.AppendOperator(ScriptOperator::OP_EQUAL);
    script = builder.Build();
    miniscript = script.GetMiniScript();
    EXPECT_STREQ(miniscript.c_str(),
        "thresh(3,c:pk(027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),sc:pk(036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),sc:pk(0211dcbf6768e8eff85d7b294776f046a5294a64158586cd2bc6da4b0740eacd2f),sdv:older(12960))");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  }

  try {
    // miniscript - The BOLT #3 to_local policy
    builder = ScriptBuilder();
    builder.AppendData(ByteData("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_NOTIF);
    builder.AppendData(ByteData("036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_ELSE);
    builder.AppendData(1008);
    builder.AppendOperator(ScriptOperator::OP_CHECKSEQUENCEVERIFY);
    builder.AppendOperator(ScriptOperator::OP_ENDIF);
    script = builder.Build();
    miniscript = script.GetMiniScript();
    EXPECT_STREQ(miniscript.c_str(),
        "andor(c:pk(027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),older(1008),c:pk(036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af))");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  }

  try {
    // miniscript - A user and a 2FA service need to sign off, but after 90 days the user alone is enough
    builder = ScriptBuilder();
    builder.AppendData(ByteData("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIGVERIFY);
    builder.AppendData(ByteData("036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_IFDUP);
    builder.AppendOperator(ScriptOperator::OP_NOTIF);
    builder.AppendData(static_cast<int64_t>(12960));
    builder.AppendOperator(ScriptOperator::OP_CHECKSEQUENCEVERIFY);
    builder.AppendOperator(ScriptOperator::OP_ENDIF);
    script = builder.Build();
    miniscript = script.GetMiniScript();
    EXPECT_STREQ(miniscript.c_str(),
        "and_v(vc:pk(027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),or_d(c:pk(036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af),older(12960)))");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  }

  try {  // fail
    // miniscript - The BOLT #3 offered HTLC policy
    builder = ScriptBuilder();
    builder.AppendData(ByteData("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_NOTIF);
    builder.AppendData(ByteData("036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIGVERIFY);
    builder.AppendData(ByteData("036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_NOTIF);
    builder.AppendOperator(ScriptOperator::OP_SIZE);
    builder.AppendData(static_cast<int64_t>(20));
    builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
    builder.AppendOperator(ScriptOperator::OP_HASH160);
    builder.AppendData(ByteData("925d4028880bd0c9d68fbc7fc7dfee976698629c"));
    builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
    builder.AppendOperator(ScriptOperator::OP_ENDIF);
    builder.AppendOperator(ScriptOperator::OP_ENDIF);
    builder.AppendOperator(ScriptOperator::OP_1);
    script = builder.Build();
    miniscript = script.GetMiniScript();
    EXPECT_STREQ(miniscript.c_str(),
        "");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  }

  try {
    // miniscript - The BOLT #3 received HTLC policy
    builder = ScriptBuilder();
    builder.AppendData(ByteData("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_NOTIF);
    builder.AppendData(ByteData("036892aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af"));
    builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
    builder.AppendOperator(ScriptOperator::OP_ELSE);
    builder.AppendOperator(ScriptOperator::OP_IF);
    builder.AppendOperator(ScriptOperator::OP_DUP);
    builder.AppendOperator(ScriptOperator::OP_HASH160);
    builder.AppendData(ByteData("925d4028880bd0c9d68fbc7fc7dfee976698629c"));
    builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
    builder.AppendOperator(ScriptOperator::OP_CHECKSIGVERIFY);
    builder.AppendOperator(ScriptOperator::OP_SIZE);
    builder.AppendData(static_cast<int64_t>(20));
    builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
    builder.AppendOperator(ScriptOperator::OP_HASH160);
    builder.AppendData(ByteData("925d4028880bd0c9d68fbc7fc7dfee976698629c"));
    builder.AppendOperator(ScriptOperator::OP_EQUAL);
    builder.AppendOperator(ScriptOperator::OP_ELSE);
    builder.AppendData(1008);
    builder.AppendOperator(ScriptOperator::OP_CHECKSEQUENCEVERIFY);
    builder.AppendOperator(ScriptOperator::OP_ENDIF);
    builder.AppendOperator(ScriptOperator::OP_ENDIF);
    script = builder.Build();
    miniscript = script.GetMiniScript();
    EXPECT_STREQ(miniscript.c_str(),
        "");
  } catch (const CfdException& e1) {
    EXPECT_STREQ("", e1.what());
  } catch (const std::exception& e2) {
    EXPECT_STREQ("", e2.what());
  }
}

