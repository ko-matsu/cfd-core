#include <vector>
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_util.h"
#include "gtest/gtest.h"

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CryptoUtil;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrPubkey;
using cfd::core::SchnorrSignature;
using cfd::core::SchnorrUtil;
using cfd::core::SigHashType;

const ByteData256 msg(
    "e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614");
const Privkey sk(
    "688c77bc2d5aaff5491cf309d4753b732135470d05b7b2cd21add0744fe97bef");
const SchnorrPubkey pubkey(
    "b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390");
const bool pubkey_parity = true;
const ByteData256 aux_rand(
    "02cce08e913f22a36c5648d6405a2c7c50106e7aa2f1649e381c7f09d16b80ab");

const Privkey nonce(
    "8c8ca771d3c25eb38de7401818eeda281ac5446f5c1396148f8d9d67592440fe");

const SchnorrSignature signature(
    "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b"
    "8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8");

TEST(SchnorrSig, Sign) {
  auto sig = SchnorrUtil::Sign(msg, sk, aux_rand);

  EXPECT_EQ(signature.GetData().GetHex(), sig.GetData().GetHex());
}

TEST(SchnorrSig, SignWithNonce) {
  std::string expected_sig =
      "5da618c1936ec728e5ccff29207f1680dcf4146370bdcfab0039951b91e3637a958e91d"
      "68537d1f6f19687cec1fd5db1d83da56ef3ade1f3c611babd7d08af42";

  auto sig = SchnorrUtil::SignWithNonce(msg, sk, nonce);

  EXPECT_EQ(expected_sig, sig.GetHex());
}

TEST(SchnorrSig, ComputeSigPoint) {
  std::string expected_sig_point =
      "03735acf82eef9da1540efb07a68251d5476dabb11ac77054924eccbb4121885e8";

  SchnorrPubkey schnorr_nonce(
      "f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b547");

  auto point = SchnorrUtil::ComputeSigPoint(msg, schnorr_nonce, pubkey);

  EXPECT_EQ(expected_sig_point, point.GetHex());
}

TEST(SchnorrSig, Verify) {
  EXPECT_TRUE(SchnorrUtil::Verify(signature, msg, pubkey));
  EXPECT_TRUE(pubkey.Verify(signature, msg));
}

TEST(SchnorrSig, GetNonce) {
  std::string expected_nonce =
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee";

  auto sig_nonce = signature.GetNonce();

  EXPECT_EQ(expected_nonce, sig_nonce.GetData().GetHex());
}

TEST(SchnorrSig, GetPrivkey) {
  std::string expected_privkey =
      "5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8";

  auto privkey = signature.GetPrivkey();

  EXPECT_EQ(expected_privkey, privkey.GetData().GetHex());
}

TEST(SchnorrSig, Constructor) {
  SchnorrSignature empty_obj;
  EXPECT_EQ(0, empty_obj.GetData().GetDataSize());
}

TEST(SchnorrPubkey, FromPrivkey) {
  auto actual_pubkey = SchnorrPubkey::FromPrivkey(sk);

  EXPECT_EQ(pubkey.GetHex(), actual_pubkey.GetHex());
  EXPECT_EQ(pubkey_parity, actual_pubkey.IsParity());
}

TEST(SchnorrPubkey, TweakAddFromPrivkey) {
  ByteData256 tweak1("45cfe14923541d2908a64f32aaf09b703dbd2cfb256830b0eebc5573b15a4476");
  Privkey tweaked_sk;
  auto actual_pubkey = SchnorrPubkey::CreateTweakAddFromPrivkey(
      sk, tweak1, &tweaked_sk);

  std::string exp_pubkey1 = "ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440";
  std::string exp_privkey1 = "dd43698cf5f96d33bf895c28d67b5ffbd736c2d4cef91e1f8ce0e38c31a709c8";

  EXPECT_EQ(exp_pubkey1, actual_pubkey.GetHex());
  EXPECT_EQ(exp_privkey1, tweaked_sk.GetHex());
  EXPECT_EQ(pubkey_parity, actual_pubkey.IsParity());

  Privkey key = sk;
  if (actual_pubkey.IsParity()) key = key.CreateNegate();
  key = key.CreateTweakAdd(tweak1);
  EXPECT_EQ(exp_privkey1, key.GetHex());
}

TEST(SchnorrPubkey, Constructor) {
  auto sk_pubkey = SchnorrPubkey::FromPrivkey(sk);
  SchnorrPubkey empty_obj;

  EXPECT_FALSE(empty_obj.IsValid());

  SchnorrPubkey sk_obj(sk);
  SchnorrPubkey b256_obj(ByteData256(sk_pubkey.GetData()));

  EXPECT_EQ(sk_pubkey.GetHex(), sk_obj.GetHex());
  EXPECT_EQ(sk_pubkey.GetHex(), b256_obj.GetHex());
  EXPECT_TRUE(sk_obj.IsValid());
  EXPECT_TRUE(b256_obj.IsValid());
  EXPECT_TRUE(sk_obj.Equals(b256_obj));
}

TEST(SchnorrPubkey, TweakAdd) {
  ByteData256 tweak1("45cfe14923541d2908a64f32aaf09b703dbd2cfb256830b0eebc5573b15a4476");
  ByteData256 tweak2("0daf700e00c25a75feb3b747a5f31ba58f4a7c3c7b36eaceef7cb882a06a9bf1");
  SchnorrPubkey tweak_pubkey1;
  SchnorrPubkey tweak_pubkey2;

  std::string exp_pubkey1 = "ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440";
  std::string exp_pubkey2 = "943203db3a9a8845a4aee1af81b76cb9ec60ab08d700df59a32426a4e6e1557b";

  EXPECT_NO_THROW(tweak_pubkey1 = pubkey.CreateTweakAdd(tweak1));
  EXPECT_EQ(exp_pubkey1, tweak_pubkey1.GetHex());
  EXPECT_TRUE(tweak_pubkey1.IsParity());

  EXPECT_NO_THROW(tweak_pubkey2 = pubkey.CreateTweakAdd(tweak2));
  EXPECT_EQ(exp_pubkey2, tweak_pubkey2.GetHex());
  EXPECT_FALSE(tweak_pubkey2.IsParity());

  EXPECT_TRUE(tweak_pubkey1.IsTweaked(pubkey, tweak1));
  EXPECT_TRUE(tweak_pubkey2.IsTweaked(pubkey, tweak2));
  EXPECT_FALSE(tweak_pubkey1.IsTweaked(pubkey, tweak2));
  bool is_parity = !tweak_pubkey2.IsParity();
  EXPECT_FALSE(tweak_pubkey2.IsTweaked(pubkey, tweak2, &is_parity));
  is_parity = !is_parity;
  EXPECT_TRUE(tweak_pubkey2.IsTweaked(pubkey, tweak2, &is_parity));

  Privkey tweak_sk1;
  Privkey tweak_sk2;
  Privkey key = sk;
  if (pubkey_parity) key = sk.CreateNegate();
  EXPECT_NO_THROW(tweak_sk1 = key.CreateTweakAdd(tweak1));
  EXPECT_NO_THROW(tweak_sk2 = key.CreateTweakAdd(tweak2));

  SchnorrPubkey tweak_pubkey21(tweak_sk1);
  SchnorrPubkey tweak_pubkey22(tweak_sk2);
  EXPECT_EQ(exp_pubkey1, tweak_pubkey21.GetHex());
  EXPECT_EQ(exp_pubkey2, tweak_pubkey22.GetHex());
}
