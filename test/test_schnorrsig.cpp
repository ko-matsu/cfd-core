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

  EXPECT_EQ(expected_sig, sig.GetData().GetHex());
}

TEST(SchnorrSig, ComputeSigPoint) {
  std::string expected_sig_point =
      "03735acf82eef9da1540efb07a68251d5476dabb11ac77054924eccbb4121885e8";

  SchnorrPubkey nonce(
      "f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b547");

  auto point = SchnorrUtil::ComputeSigPoint(msg, nonce, pubkey);

  EXPECT_EQ(expected_sig_point, point.GetHex());
}

TEST(SchnorrSig, Verify) {
  EXPECT_TRUE(SchnorrUtil::Verify(signature, msg, pubkey));
}

TEST(SchnorrSig, GetNonce) {
  std::string expected_nonce =
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee";

  auto nonce = signature.GetNonce();

  EXPECT_EQ(expected_nonce, nonce.GetData().GetHex());
}

TEST(SchnorrSig, GetPrivkey) {
  std::string expected_privkey =
      "5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8";

  auto privkey = signature.GetPrivkey();

  EXPECT_EQ(expected_privkey, privkey.GetData().GetHex());
}

TEST(SchnorrPubkey, FromPrivkey) {
  auto actual_pubkey = SchnorrPubkey::FromPrivkey(sk);

  EXPECT_EQ(pubkey.GetData().GetHex(), actual_pubkey.GetData().GetHex());
}
