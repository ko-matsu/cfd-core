#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_descriptor.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_key.h"

using cfd::core::Txid;
using cfd::core::ByteData;
using cfd::core::CfdException;
using cfd::core::Descriptor;
using cfd::core::DescriptorNode;
using cfd::core::DescriptorNodeType;
using cfd::core::DescriptorScriptType;
using cfd::core::DescriptorKeyType;
using cfd::core::Script;
using cfd::core::Address;
using cfd::core::AddressFormatData;
using cfd::core::Pubkey;

TEST(Descriptor, Parse_pk) {
  cfd::core::CfdCoreHandle handle = nullptr;
  cfd::core::Initialize(&handle);
  std::string descriptor = "pk(02a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff397)#rk5v7uqw";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
    "02a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff397 OP_CHECKSIG");
}

TEST(Descriptor, Parse_pkh) {
  std::string descriptor = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_DUP OP_HASH160 06afd46bcdfd22ef94ac122aa11f241244a37ecc OP_EQUALVERIFY OP_CHECKSIG");
}

TEST(Descriptor, Parse_wpkh) {
  std::string descriptor = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 7dd65592d0ab2fe0d0257d571abf032cd9db93dc");
}

TEST(Descriptor, Parse_sh_wpkh) {
  std::string descriptor = "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  Script redeem_script;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript(&redeem_script));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 cc6ffbc0bf31af759451068f90ba7a0272b6b332 OP_EQUAL");
  EXPECT_STREQ(redeem_script.ToString().c_str(),
      "0 7fda9cf020c16cacf529c87d8de89bfc70b8c9cb");
}

TEST(Descriptor, Parse_multi) {
  std::string descriptor = "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  Script redeem_script;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript(&redeem_script));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "1 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc 2 OP_CHECKMULTISIG");
  EXPECT_STREQ(redeem_script.ToString().c_str(),
      "1 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc 2 OP_CHECKMULTISIG");
}

TEST(Descriptor, Parse_sh_multi) {
  std::string descriptor = "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  Script redeem_script;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  try {
    desc = Descriptor::Parse(descriptor);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
  EXPECT_NO_THROW(locking_script = desc.GetScript(&redeem_script));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 a6a8b030a38762f4c1f5cbe387b61a3c5da5cd26 OP_EQUAL");
  EXPECT_STREQ(redeem_script.ToString().c_str(),
      "2 022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01 03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe 2 OP_CHECKMULTISIG");
}

TEST(Descriptor, Parse_addr) {
  std::string descriptor = "addr(bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 c7a1f1a4d6b4c1802a59631966a18359de779e8a6a65973735a3ccdfdabc407d");
}

TEST(Descriptor, Parse_raw) {
  std::string descriptor = "raw(6a4c4f54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e)#zf2avljj";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(), "OP_RETURN 54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e");
}
