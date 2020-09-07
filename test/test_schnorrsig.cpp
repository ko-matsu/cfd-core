#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_util.h"
#include "gtest/gtest.h"

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CryptoUtil;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrNonce;
using cfd::core::SchnorrSignature;
using cfd::core::SchnorrUtil;
using cfd::core::SigHashType;

const ByteData256 msg(
    "e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614");
const Privkey sk(
    "688c77bc2d5aaff5491cf309d4753b732135470d05b7b2cd21add0744fe97bef");
const Pubkey pubkey(
    "02b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390");
const ByteData256 aux_rand(
    "02cce08e913f22a36c5648d6405a2c7c50106e7aa2f1649e381c7f09d16b80ab");

const Privkey nonce(
    "8c8ca771d3c25eb38de7401818eeda281ac5446f5c1396148f8d9d67592440fe");

const SchnorrNonce schnorr_nonce(
    "f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b547");

const SchnorrSignature signature(
    "f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b5477c988c51"
    "634a8dc955950a58ff5dc8c506ddb796121e6675946312680c26cf33");

TEST(SchnorrSig, Sign) {
  auto sig = SchnorrUtil::Sign(msg, sk, aux_rand);

  EXPECT_EQ(signature.GetData().GetHex(), sig.GetData().GetHex());
}

TEST(SchnorrSig, SignWithNonce) {
  std::string expected_sig =
      "5da618c1936ec728e5ccff29207f1680dcf4146370bdcfab0039951b91e3637a50a2a86"
      "0b130d009405511c3eafe943e157a0df2c2020e3e50df05adb175332f";

  auto sig = SchnorrUtil::SignWithNonce(msg, sk, nonce);

  EXPECT_EQ(expected_sig, sig.GetData().GetHex());
}

TEST(SchnorrSig, ComputeSigPoint) {
  std::string expected_sig_point =
      "020d17280b8d2c2bd3b597b4446419c151dc237353d0fb9ec03d4eb7e8de7ee0a8";

  auto point = SchnorrUtil::ComputeSigPoint(msg, schnorr_nonce, pubkey);

  EXPECT_EQ(expected_sig_point, point.GetHex());
}

TEST(SchnorrSig, Verify) {
  EXPECT_TRUE(SchnorrUtil::Verify(signature, msg, pubkey));
}

TEST(SchnorrSig, GetSchnorrNonce) {
  std::string expected_nonce =
      "f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b547";

  auto nonce = signature.GetNonce();

  EXPECT_EQ(expected_nonce, nonce.GetData().GetHex());
}

TEST(SchnorrSig, GetPrivkey) {
  std::string expected_privkey =
      "7c988c51634a8dc955950a58ff5dc8c506ddb796121e6675946312680c26cf33";

  auto privkey = signature.GetPrivkey();

  EXPECT_EQ(expected_privkey, privkey.GetData().GetHex());
}
