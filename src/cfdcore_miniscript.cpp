// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// miniscript: https://github.com/sipa/miniscript

#include <string>
#include <vector>

#include "cfdcore/cfdcore_script.h"
#include "cfdcore_miniscript.h"

namespace cfd {
namespace core {


template<typename NumType>
static std::vector<MaxInt<NumType>> CreateMaxIntList(MaxInt<NumType> data)
{
    std::vector<MaxInt<NumType>> ret;
    ret.push_back(data);
    return ret;
}
#if 0
//! Literal operator to construct Type objects.
Type operator"" _mst(const char* c, size_t l) {
    return l == 0 ? Type(0) : operator"" _mst(c + 1, l - 1) | Type(
        *c == 'B' ? 1 << 0 : // Base type
        *c == 'V' ? 1 << 1 : // Verify type
        *c == 'K' ? 1 << 2 : // Key type
        *c == 'W' ? 1 << 3 : // Wrapped type
        *c == 'z' ? 1 << 4 : // Zero-arg property
        *c == 'o' ? 1 << 5 : // One-arg property
        *c == 'n' ? 1 << 6 : // Nonzero arg property
        *c == 'd' ? 1 << 7 : // Dissatisfiable property
        *c == 'u' ? 1 << 8 : // Unit property
        *c == 'e' ? 1 << 9 : // Expression property
        *c == 'f' ? 1 << 10 : // Forced property
        *c == 's' ? 1 << 11 : // Safe property
        *c == 'm' ? 1 << 12 : // Nonmalleable property
        *c == 'x' ? 1 << 13 : // Expensive verify
        (throw std::logic_error("Unknown character in _mst literal"), 0)
    );
}
#endif

//! Literal operator to construct Type objects.
Type ConvStr(const char* c) {
  size_t l = strlen(c);
  return l == 0 ? Type(0) : ConvStr(c + 1) | Type(
      *c == 'B' ? 1 << 0 : // Base type
      *c == 'V' ? 1 << 1 : // Verify type
      *c == 'K' ? 1 << 2 : // Key type
      *c == 'W' ? 1 << 3 : // Wrapped type
      *c == 'z' ? 1 << 4 : // Zero-arg property
      *c == 'o' ? 1 << 5 : // One-arg property
      *c == 'n' ? 1 << 6 : // Nonzero arg property
      *c == 'd' ? 1 << 7 : // Dissatisfiable property
      *c == 'u' ? 1 << 8 : // Unit property
      *c == 'e' ? 1 << 9 : // Expression property
      *c == 'f' ? 1 << 10 : // Forced property
      *c == 's' ? 1 << 11 : // Safe property
      *c == 'm' ? 1 << 12 : // Nonmalleable property
      *c == 'x' ? 1 << 13 : // Expensive verify
      (throw std::logic_error("Unknown character in ConvStr literal"), 0)
  );
}

bool IsSpace(char c) {
    return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v';
}

char HexDigit(char c)
{
  static const signed char p_util_hexdigit[256] =
  { -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
    -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };
  return p_util_hexdigit[(uint8_t)c];
}

static std::vector<uint8_t> ParseHex(const std::string& str)
{
  // convert hex dump to vector
  const char* psz = str.c_str();
  std::vector<uint8_t> vch;
  while (true)
  {
      while (IsSpace(*psz))
          psz++;
      char c = HexDigit(*psz++);
      if (c == (char)-1)
          break;
      uint8_t n = (c << 4);
      c = HexDigit(*psz++);
      if (c == (signed char)-1)
          break;
      n |= c;
      vch.push_back(n);
  }
  return vch;
}

std::vector<std::vector<uint8_t>> CreateVectorList(std::vector<uint8_t> arr)
{
    std::vector<std::vector<uint8_t>> ret;
    ret.push_back(arr);
    return ret;
}

#if 0

inline std::vector<ByteData> CreateByteArray(std::vector<uint8_t> arr)
{
    std::vector<ByteData> ret;
    ret.push_back(ByteData(arr));
    return ret;
}

bool Func(const std::string& str, std::vector<const char>& sp, std::string* out)
{
    if ((size_t)sp.size() >= str.size() + 2 && sp[str.size()] == '(' && sp[sp.size() - 1] == ')' && std::equal(str.begin(), str.end(), sp.begin())) {
        *out = std::string(sp.begin() + str.size() + 1, sp.end() - str.size() + 2);  // sp.end() - str.size() + 2
        return true;
    }
    return false;
}
#endif

bool Func(const std::string& str, const std::string& sp, std::string* out)
{
    if ((size_t)sp.size() >= str.size() + 2 && sp[str.size()] == '(' && sp[sp.size() - 1] == ')') {
      std::string sub_str = sp.substr(0, str.size());
      if (sub_str == str) {
        *out = sp.substr(str.size() + 1, sp.size() - str.size() + 2);  // sp.end() - str.size() + 2
        return true;
      }
    }
    return false;
}


bool Const(const std::string& str, const std::string& sp, std::string* out)
{
    if ((size_t)sp.size() >= str.size()) {
      std::string sub_str = sp.substr(0, str.size());
      if (sub_str == str) {
        *out = sp.substr(str.size());
        return true;
      }
    }
    return false;
}

std::string Expr(const std::string& sp, std::string* out)
{
    int level = 0;
    auto it = sp.begin();
    while (it != sp.end()) {
        if (*it == '(') {
            ++level;
        } else if (level && *it == ')') {
            --level;
        } else if (level == 0 && (*it == ')' || *it == ',')) {
            break;
        }
        ++it;
    }
    std::string ret = std::string(sp.begin(), it);
    *out = std::string(it, sp.end());
    return ret;
}

static bool ParsePrechecks(const std::string& str)
{
    if (str.empty()) // No empty string allowed
        return false;
    if (str.size() >= 1 && (IsSpace(str[0]) || IsSpace(str[str.size()-1]))) // No padding allowed
        return false;
    if (str.size() != strlen(str.c_str())) // No embedded NUL characters allowed
        return false;
    return true;
}

bool ParseInt64(const std::string& str, int64_t *out)
{
    if (!ParsePrechecks(str))
        return false;
    char *endp = nullptr;
    errno = 0; // strtoll will not set errno if valid
    long long int n = strtoll(str.c_str(), &endp, 10);
    if(out) *out = (int64_t)n;
    // Note that strtoll returns a *long long int*, so even if strtol doesn't report an over/underflow
    // we still have to check that the returned value is within the range of an *int64_t*.
    return endp && *endp == 0 && !errno &&
        n >= std::numeric_limits<int64_t>::min() &&
        n <= std::numeric_limits<int64_t>::max();
}


Node Parse(std::string in, const MiniScriptConverter& ctx, int recursion_depth, std::string* out) {
  if (recursion_depth >= MAX_PARSE_RECURSION) {
      throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
  }
  auto expr = Expr(in, out);
  std::string temp_out;
  // Parse wrappers
  for (size_t i = 0; i < expr.size(); ++i) {
      if (expr[i] == ':') {
          auto in2 = std::string(expr.begin() + 1, expr.end());
          Node sub = Parse(in2, ctx, recursion_depth + 1, &temp_out);
          if (temp_out.size()) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
          for (size_t j = i; j-- > 0; ) {
              if (expr[j] == 'a') {
                  sub = Node(NodeType::WRAP_A, std::vector<Node>{sub});
              } else if (expr[j] == 's') {
                  sub = Node(NodeType::WRAP_S, std::vector<Node>{sub});
              } else if (expr[j] == 'c') {
                  sub = Node(NodeType::WRAP_C, std::vector<Node>{sub});
              } else if (expr[j] == 'd') {
                  sub = Node(NodeType::WRAP_D, std::vector<Node>{sub});
              } else if (expr[j] == 'j') {
                  sub = Node(NodeType::WRAP_J, std::vector<Node>{sub});
              } else if (expr[j] == 'n') {
                  sub = Node(NodeType::WRAP_N, std::vector<Node>{sub});
              } else if (expr[j] == 'v') {
                  sub = Node(NodeType::WRAP_V, std::vector<Node>{sub});
              } else if (expr[j] == 't') {
                  sub = Node(NodeType::AND_V, std::vector<Node>{sub, Node(NodeType::JUST_1)});
              } else if (expr[j] == 'u') {
                  sub = Node(NodeType::OR_I, std::vector<Node>{sub, Node(NodeType::JUST_0)});
              } else if (expr[j] == 'l') {
                  sub = Node(NodeType::OR_I, std::vector<Node>{Node(NodeType::JUST_0), sub});
              } else {
                  throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
              }
          }
          return sub;
      }
      if (expr[i] < 'a' || expr[i] > 'z') break;
  }
  // Parse the other node types
  NodeType nodetype;
  std::string func_out;
  if (expr == "0") {
      return Node(NodeType::JUST_0);
  } else if (expr == "1") {
      return Node(NodeType::JUST_1);
  } else if (Func("pk", expr, &func_out)) {
      ByteData key;
      if (ctx.FromString(func_out, key)) {
          return Node(NodeType::PK, std::vector<ByteData>{key});
      }
      throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__) + ", func_out=" + func_out);
  } else if (Func("pk_h", expr, &func_out)) {
      ByteData key;
      if (ctx.FromString(func_out, key)) {
          return Node(NodeType::PK_H, std::vector<ByteData>{key});
      }
      throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
  } else if (expr == "0") {
      return Node(NodeType::JUST_0);
  } else if (expr == "1") {
      return Node(NodeType::JUST_1);
  } else if (Func("sha256", expr, &func_out)) {
      auto hash = ParseHex(func_out);
      if (hash.size() != 32) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      return Node(NodeType::SHA256, hash);
  } else if (Func("ripemd160", expr, &func_out)) {
      auto hash = ParseHex(func_out);
      if (hash.size() != 20) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      return Node(NodeType::RIPEMD160, hash);
  } else if (Func("hash256", expr, &func_out)) {
      auto hash = ParseHex(func_out);
      if (hash.size() != 32) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      return Node(NodeType::HASH256, hash);
  } else if (Func("hash160", expr, &func_out)) {
      auto hash = ParseHex(func_out);
      if (hash.size() != 20) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      return Node(NodeType::HASH160, hash);
  } else if (Func("after", expr, &func_out)) {
      int64_t num;
      if (!ParseInt64(func_out, &num)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      if (num < 1 || num >= 0x80000000L) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      return Node(NodeType::AFTER, num);
  } else if (Func("older", expr, &func_out)) {
      int64_t num;
      if (!ParseInt64(std::string(expr.begin(), expr.end()), &num)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      if (num < 1 || num >= 0x80000000L) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      return Node(NodeType::OLDER, num);
  } else if (Func("and_n", expr, &func_out)) {
      auto left = Parse(func_out, ctx, recursion_depth + 1, &temp_out);
      std::string temp_out2;
      if (!Const(",", temp_out, &temp_out2)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      std::string temp_out3;
      auto right = Parse(temp_out2, ctx, recursion_depth + 1, &temp_out3);
      if (temp_out3.size()) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      return Node(NodeType::ANDOR, std::vector<Node>{left, right, Node(NodeType::JUST_0)});
  } else if (Func("andor", expr, &func_out)) {
      std::string temp_out2;
      std::string temp_out3;
      std::string temp_out4;
      std::string temp_out5;
      auto left = Parse(func_out, ctx, recursion_depth + 1, &temp_out);
      if (!Const(",", temp_out, &temp_out2)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      auto mid = Parse(temp_out2, ctx, recursion_depth + 1, &temp_out3);
      if (!Const(",", temp_out3, &temp_out4)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      auto right = Parse(temp_out4, ctx, recursion_depth + 1, &temp_out5);
      if (temp_out5.size()) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      return Node(NodeType::ANDOR, std::vector<Node>{left, mid, right});
  } else if (Func("thresh_m", expr, &func_out)) {
      std::string temp_out2;
      auto arg = Expr(func_out, &temp_out2);
      int64_t count;
      if (!ParseInt64(arg, &count)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      std::vector<ByteData> keys;
      while (expr.size()) {
          if (!Const(",", expr, &temp_out)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
          auto keyarg = Expr(temp_out, &temp_out2);
          ByteData key;
          if (!ctx.FromString(keyarg, key)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
          keys.push_back(key);
      }
      if (keys.size() < 1 || keys.size() > 20) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      if (count < 1 || count > (int64_t)keys.size()) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      return Node(NodeType::THRESH_M, keys, count);
  } else if (Func("thresh", expr, &func_out)) {
      std::string temp_out2;
      auto arg = Expr(func_out, &temp_out2);
      int64_t count;
      if (!ParseInt64(arg, &count)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      std::vector<Node> subs;
      while (expr.size()) {
          temp_out = expr;
          expr = "";
          if (!Const(",", temp_out, &expr)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
          temp_out = "";
          auto sub = Parse(expr, ctx, recursion_depth + 1, &temp_out);
          subs.push_back(sub);
          expr = temp_out;
      }
      if (count <= 1 || count >= (int64_t)subs.size()) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__));
      return Node(NodeType::THRESH, subs, std::vector<ByteData>(0), static_cast<uint32_t>(count));
  } else if (Func("and_v", expr, &func_out)) {
      nodetype = NodeType::AND_V;
  } else if (Func("and_b", expr, &func_out)) {
      nodetype = NodeType::AND_B;
  } else if (Func("or_c", expr, &func_out)) {
      nodetype = NodeType::OR_C;
  } else if (Func("or_b", expr, &func_out)) {
      nodetype = NodeType::OR_B;
  } else if (Func("or_d", expr, &func_out)) {
      nodetype = NodeType::OR_D;
  } else if (Func("or_i", expr, &func_out)) {
      nodetype = NodeType::OR_I;
  } else {
      throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__) + ", expr=" + expr);
  }
  expr = func_out;
  auto left = Parse(expr, ctx, recursion_depth + 1, &temp_out);
  expr = "";
  if (!Const(",", temp_out, &expr)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__) + ", temp_out=" + temp_out);
  auto right = Parse(expr, ctx, recursion_depth + 1, &temp_out);
  if (temp_out == ")") {
    // do nothing
  }
  else if (temp_out.size()) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "Parse error. line=" + std::to_string(__LINE__) + ", temp_out=" + temp_out);
  return Node(nodetype, std::vector<Node>{left, right});
}

bool CheckIte(ScriptObjectIte& in, ScriptObject last) {
  if (last == in) {
    throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, "CheckIte error. line=" + std::to_string(__LINE__));
  }
  return true;
}

Node DecodeSingle(ScriptObjectIte& in, ScriptObject last, const MiniScriptConverter& ctx) {

    std::vector<Node> subs;
    std::vector<ByteData> keys;
    int64_t k;

    if (CheckIte(in, last) && in[0].first == ScriptOperator::OP_1) {
        ++in;
        return Node(NodeType::JUST_1);
    }
    if (CheckIte(in, last) && in[0].first == ScriptOperator::OP_0) {
        ++in;
        return Node(NodeType::JUST_0);
    }
    if (CheckIte(in, last) && in[0].second.size() == 33) {
        ByteData key;
        if (!ctx.FromPKBytes(std::vector<uint8_t>(in[0].second.begin(), in[0].second.end()), key)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        ++in;
        return Node(NodeType::PK, std::vector<ByteData>{key});
    }
    if (CheckIte(in, last) && in[0].second.size() == 20) {
        ByteData key;
        if (!ctx.FromPKHBytes(std::vector<uint8_t>(in[0].second.begin(), in[0].second.end()), key)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        ++in;
        return Node(NodeType::PK_H, std::vector<ByteData>{key});
    }
    if (last - in >= 5 && in[0].first == ScriptOperator::OP_VERIFY && in[1].first == ScriptOperator::OP_EQUAL && in[3].first == ScriptOperator::OP_HASH160 && in[4].first == ScriptOperator::OP_DUP && in[2].second.size() == 20) {
        ByteData key;
        if (!ctx.FromPKHBytes(std::vector<uint8_t>(in[2].second.begin(), in[2].second.end()), key)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        in += 5;
        return Node(NodeType::PK_H, std::vector<ByteData>{key});
    }
    // ADD
    if (last - in >= 5 && in[0].first == ScriptOperator::OP_EQUAL && in[1].second.size() == 20 && in[2].first == ScriptOperator::OP_HASH160 && in[3].first == ScriptOperator::OP_VERIFY && in[4].first == ScriptOperator::OP_EQUAL) {
        ByteData key;
        if (!ctx.FromPKHBytes(std::vector<uint8_t>(in[1].second.begin(), in[1].second.end()), key)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        in += 5;
        return Node(NodeType::PK_H, std::vector<ByteData>{key});
    }
    if (last - in >= 2 && in[0].first == ScriptOperator::OP_CHECKSEQUENCEVERIFY && ParseScriptNumber(in[1], k)) {
        in += 2;
        if (k < 1 || k > 0x7FFFFFFFL) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        return Node(NodeType::OLDER, k);
    }
    if (last - in >= 2 && in[0].first == ScriptOperator::OP_CHECKLOCKTIMEVERIFY && ParseScriptNumber(in[1], k)) {
        in += 2;
        if (k < 1 || k > 0x7FFFFFFFL) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        return Node(NodeType::AFTER, k);
    }
    if (last - in >= 7 && in[0].first == ScriptOperator::OP_EQUAL && in[1].second.size() == 32 && in[2].first == ScriptOperator::OP_SHA256 && in[3].first == ScriptOperator::OP_VERIFY && in[4].first == ScriptOperator::OP_EQUAL && ParseScriptNumber(in[5], k) && k == 32 && in[6].first == ScriptOperator::OP_SIZE) {
        in += 7;
        return Node(NodeType::SHA256, in[-6].second);
    }
    if (last - in >= 7 && in[0].first == ScriptOperator::OP_EQUAL && in[1].second.size() == 20 && in[2].first == ScriptOperator::OP_RIPEMD160 && in[3].first == ScriptOperator::OP_VERIFY && in[4].first == ScriptOperator::OP_EQUAL && ParseScriptNumber(in[5], k) && k == 32 && in[6].first == ScriptOperator::OP_SIZE) {
        in += 7;
        return Node(NodeType::RIPEMD160, in[-6].second);
    }
    if (last - in >= 7 && in[0].first == ScriptOperator::OP_EQUAL && in[1].second.size() == 32 && in[2].first == ScriptOperator::OP_HASH256 && in[3].first == ScriptOperator::OP_VERIFY && in[4].first == ScriptOperator::OP_EQUAL && ParseScriptNumber(in[5], k) && k == 32 && in[6].first == ScriptOperator::OP_SIZE) {
        in += 7;
        return Node(NodeType::HASH256, in[-6].second);
    }
    if (last - in >= 7 && in[0].first == ScriptOperator::OP_EQUAL && in[1].second.size() == 20 && in[2].first == ScriptOperator::OP_HASH160 && in[3].first == ScriptOperator::OP_VERIFY && in[4].first == ScriptOperator::OP_EQUAL && ParseScriptNumber(in[5], k) && k == 32 && in[6].first == ScriptOperator::OP_SIZE) {
        in += 7;
        return Node(NodeType::HASH160, in[-6].second);
    }
    if (last - in >= 2 && in[0].first == ScriptOperator::OP_CHECKSIG) {
        ++in;
        auto sub = DecodeSingle(in, last, ctx);
        return Node(NodeType::WRAP_C, std::vector<Node>{sub});
    }
    if (last - in >= 3 && in[0].first == ScriptOperator::OP_BOOLAND) {
        ++in;
        auto sub1 = DecodeWrapped(in, last, ctx);
        auto sub2 = DecodeSingle(in, last, ctx);
        return Node(NodeType::AND_B, std::vector<Node>{sub2, sub1});
    }
    if (last - in >= 3 && in[0].first == ScriptOperator::OP_BOOLOR) {
        ++in;
        auto sub1 = DecodeWrapped(in, last, ctx);
        auto sub2 = DecodeSingle(in, last, ctx);
        return Node(NodeType::OR_B, std::vector<Node>{sub2, sub1});
    }
    if (last - in >= 2 && in[0].first == ScriptOperator::OP_VERIFY) {
        ++in;
        auto sub = DecodeSingle(in, last, ctx);
        return Node(NodeType::WRAP_V, std::vector<Node>{sub});
    }
    if (last - in >= 2 && in[0].first == ScriptOperator::OP_0NOTEQUAL) {
        ++in;
        auto sub = DecodeSingle(in, last, ctx);
        return Node(NodeType::WRAP_N, std::vector<Node>{sub});
    }
    if (CheckIte(in, last) && in[0].first == ScriptOperator::OP_ENDIF) {
        ++in;
        if (last - in == 0) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        Node sub1 = DecodeMulti(in, last, ctx);
        bool have_else = false;
        Node sub2(NodeType::JUST_0);
        if (last - in == 0) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        if (in[0].first == ScriptOperator::OP_ELSE) {
          ++in;
          have_else = true;
          sub2 = DecodeMulti(in, last, ctx);
        }
        if (last - in == 0 || (in[0].first != ScriptOperator::OP_IF && in[0].first != ScriptOperator::OP_NOTIF)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        bool negated = (in[0].first == ScriptOperator::OP_NOTIF);
        ++in;

        if (!have_else && !negated) {
            if (CheckIte(in, last) && in[0].first == ScriptOperator::OP_DUP) {
                ++in;
                return Node(NodeType::WRAP_D, std::vector<Node>{sub1});
            }
            if (last - in >= 2 && in[0].first == ScriptOperator::OP_0NOTEQUAL && in[1].first == ScriptOperator::OP_SIZE) {
                in += 2;
                return Node(NodeType::WRAP_J, std::vector<Node>{sub1});
            }
            throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        }
        if (have_else && negated) {
            auto sub3 = DecodeSingle(in, last, ctx);
            return Node(NodeType::ANDOR, std::vector<Node>{sub3, sub1, sub2});
        }
        if (!have_else && negated) {
            if (last - in >= 2 && in[0].first == ScriptOperator::OP_IFDUP) {
                ++in;
                auto sub3 = DecodeSingle(in, last, ctx);
                return Node(NodeType::OR_D, std::vector<Node>{sub3, sub1});
            }
            if (CheckIte(in, last)) {
                auto sub3 = DecodeSingle(in, last, ctx);
                return Node(NodeType::OR_C, std::vector<Node>{sub3, sub1});
            }
            throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        }
        if (have_else && !negated) {
            return Node(NodeType::OR_I, std::vector<Node>{sub2, sub1});
        }
        throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    }
    keys.clear();
    if (last - in >= 3 && in[0].first == ScriptOperator::OP_CHECKMULTISIG) {
        int64_t n;
        if (!ParseScriptNumber(in[1], n)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        if (last - in < 3 + n) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        if (n < 1 || n > 20) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        for (int i = 0; i < n; ++i) {
            ByteData key;
            if (in[2 + i].second.size() != 33) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
            if (!ctx.FromPKBytes(std::vector<uint8_t>(in[2 + i].second.begin(), in[2 + i].second.end()), key)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
            keys.push_back(key);
        }
        if (!ParseScriptNumber(in[2 + n], k)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        if (k < 1 || k > n) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
        // in += 3 + n;
        for (int i = 0; i < n + 3; ++i)
          ++in;
        std::reverse(keys.begin(), keys.end());
        return Node(NodeType::THRESH_M, keys, k);
    }
    subs.clear();
    if (last - in >= 3 && in[0].first == ScriptOperator::OP_EQUAL && ParseScriptNumber(in[1], k)) {
        in += 2;
        while (last - in >= 2 && in[0].first == ScriptOperator::OP_ADD) {
            ++in;
            auto sub = DecodeWrapped(in, last, ctx);
            subs.push_back(sub);
        }
        auto sub = DecodeSingle(in, last, ctx);
        subs.push_back(sub);
        std::reverse(subs.begin(), subs.end());
        return Node(NodeType::THRESH, subs, std::vector<ByteData>(0), static_cast<uint32_t>(k));
    }

    std::string result;
    for (ScriptObjectIte it = in; it != last; ++it) {
      // result += it->first.ToString();
      result += std::to_string((int)it->first.GetDataType());
      result += "(";
      result += std::to_string((int)it->second.size());
      result += ")";
      result += " ";
    }
    throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__) + ", in=" + result);
}

//! Decode a list of script elements into a miniscript (except a: and s:)
Node DecodeMulti(ScriptObjectIte& in, ScriptObject last, const MiniScriptConverter& ctx) {
    if (in == last) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    auto sub = DecodeSingle(in, last, ctx);
    while (in != last && in[0].first != ScriptOperator::OP_ELSE && in[0].first != ScriptOperator::OP_IF && in[0].first != ScriptOperator::OP_NOTIF && in[0].first != ScriptOperator::OP_TOALTSTACK && in[0].first != ScriptOperator::OP_SWAP) {
        auto sub2 = DecodeSingle(in, last, ctx);
        sub = Node(NodeType::AND_V, std::vector<Node>{sub2, sub});
    }
    return sub;
}

//! Decode a list of script elements into a miniscript (only a: and s:)
Node DecodeWrapped(ScriptObjectIte& in, ScriptObject last, const MiniScriptConverter& ctx) {
  if (last - in >= 3 && in[0].first == ScriptOperator::OP_FROMALTSTACK) {
    ++in;
    auto sub = DecodeMulti(in, last, ctx);
    if (in == last || in[0].first != ScriptOperator::OP_TOALTSTACK) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    ++in;
    return Node(NodeType::WRAP_A, std::vector<Node>{sub});
  }
  auto sub = DecodeMulti(in, last, ctx);
  if (in == last || in[0].first != ScriptOperator::OP_SWAP) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
  ++in;
  return Node(NodeType::WRAP_S, std::vector<Node>{sub});
}


/**
 * @brief miniscript文字列からScript Nodeを生成します。
 */
Node FromString(const std::string& str, const MiniScriptConverter& ctx) {
    std::string temp_out;
    auto ret = Parse(str, ctx, 0, &temp_out);
    if (temp_out.size()) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    return ret;
}

/**
 * @brief ScriptからScript Nodeを生成します。
 */
Node FromScript(const Script& script, const MiniScriptConverter& ctx) {
    std::vector<std::pair<ScriptOperator, std::vector<uint8_t>>> decomposed;
    if (!DecomposeScript(script, decomposed)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    auto it = decomposed.begin();
    auto ret = DecodeMulti(it, decomposed.end(), ctx);
    if (it != decomposed.end()) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    return ret;
}

//! Compute the length of the script for this miniscript (including children).
size_t Node::CalcScriptLen() const {
  size_t subsize = 0;
  for (const auto& sub : subs) {
      subsize += sub.ScriptSize();
  }
  Type sub0type = subs.size() > 0 ? subs[0].GetType() : Type(0);
  return ComputeScriptLen(nodetype, sub0type, subsize, k, subs.size(), keys.size());
}

//! Compute the type for this miniscript.
Type Node::CalcType() const {
  // THRESH has a variable number of subexpression
  std::vector<Type> sub_types;
  if (nodetype == NodeType::THRESH) {
      for (const auto& sub : subs) sub_types.push_back(sub.GetType());
  }
  // All other nodes than THRESH can be computed just from the types of the 0-3 subexpexpressions.
  Type x = subs.size() > 0 ? subs[0].GetType() : Type(0);
  Type y = subs.size() > 1 ? subs[1].GetType() : Type(0);
  Type z = subs.size() > 2 ? subs[2].GetType() : Type(0);

  return SanitizeType(ComputeType(nodetype, x, y, z, sub_types, k, data.GetDataSize(), subs.size(), keys.size()));
}

//! Internal code for ToScript.
ScriptBuilder Node::MakeScript(const MiniScriptConverter& ctx, bool verify) const {


  std::vector<uint8_t> bytes;
  switch (nodetype) {
      case NodeType::PK: return ScriptBuilder() << ctx.ToPKBytes(keys[0]);
      case NodeType::PK_H: return ScriptBuilder() << ScriptOperator::OP_DUP << ScriptOperator::OP_HASH160 << ctx.ToPKHBytes(keys[0]) << ScriptOperator::OP_EQUALVERIFY;
      case NodeType::OLDER: return ScriptBuilder() << k << ScriptOperator::OP_CHECKSEQUENCEVERIFY;
      case NodeType::AFTER: return ScriptBuilder() << k << ScriptOperator::OP_CHECKLOCKTIMEVERIFY;
      case NodeType::SHA256: return ScriptBuilder() << ScriptOperator::OP_SIZE << 32 << ScriptOperator::OP_EQUALVERIFY << ScriptOperator::OP_SHA256 << data << (verify ? ScriptOperator::OP_EQUALVERIFY : ScriptOperator::OP_EQUAL);
      case NodeType::RIPEMD160: return ScriptBuilder() << ScriptOperator::OP_SIZE << 32 << ScriptOperator::OP_EQUALVERIFY << ScriptOperator::OP_RIPEMD160 << data << (verify ? ScriptOperator::OP_EQUALVERIFY : ScriptOperator::OP_EQUAL);
      case NodeType::HASH256: return ScriptBuilder() << ScriptOperator::OP_SIZE << 32 << ScriptOperator::OP_EQUALVERIFY << ScriptOperator::OP_HASH256 << data << (verify ? ScriptOperator::OP_EQUALVERIFY : ScriptOperator::OP_EQUAL);
      case NodeType::HASH160: return ScriptBuilder() << ScriptOperator::OP_SIZE << 32 << ScriptOperator::OP_EQUALVERIFY << ScriptOperator::OP_HASH160 << data << (verify ? ScriptOperator::OP_EQUALVERIFY : ScriptOperator::OP_EQUAL);
      case NodeType::WRAP_A: return (ScriptBuilder() << ScriptOperator::OP_TOALTSTACK) + subs[0].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_FROMALTSTACK);
      case NodeType::WRAP_S: return (ScriptBuilder() << ScriptOperator::OP_SWAP) + subs[0].MakeScript(ctx, verify);
      case NodeType::WRAP_C: return subs[0].MakeScript(ctx) + ScriptBuilder() << (verify ? ScriptOperator::OP_CHECKSIGVERIFY : ScriptOperator::OP_CHECKSIG);
      case NodeType::WRAP_D: return (ScriptBuilder() << ScriptOperator::OP_DUP << ScriptOperator::OP_IF) + subs[0].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_ENDIF);
      case NodeType::WRAP_V: return subs[0].MakeScript(ctx, true) + (subs[0].GetType() << ConvStr("x") ? (ScriptBuilder() << ScriptOperator::OP_VERIFY) : ScriptBuilder());
      case NodeType::WRAP_J: return (ScriptBuilder() << ScriptOperator::OP_SIZE << ScriptOperator::OP_0NOTEQUAL << ScriptOperator::OP_IF) + subs[0].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_ENDIF);
      case NodeType::WRAP_N: return subs[0].MakeScript(ctx) + ScriptBuilder() << ScriptOperator::OP_0NOTEQUAL;
      case NodeType::JUST_1: return (ScriptBuilder() << ScriptOperator::ScriptOperator::OP_1);
      case NodeType::JUST_0: return (ScriptBuilder() << ScriptOperator::ScriptOperator::OP_0);
      case NodeType::AND_V: return subs[0].MakeScript(ctx) + subs[1].MakeScript(ctx, verify);
      case NodeType::AND_B: return subs[0].MakeScript(ctx) + subs[1].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_BOOLAND);
      case NodeType::OR_B: return subs[0].MakeScript(ctx) + subs[1].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_BOOLOR);
      case NodeType::OR_D: return subs[0].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_IFDUP << ScriptOperator::OP_NOTIF) + subs[1].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_ENDIF);
      case NodeType::OR_C: return subs[0].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_NOTIF) + subs[1].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_ENDIF);
      case NodeType::OR_I: return (ScriptBuilder() << ScriptOperator::OP_IF) + subs[0].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_ELSE) + subs[1].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_ENDIF);
      case NodeType::ANDOR: return subs[0].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_NOTIF) + subs[2].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_ELSE) + subs[1].MakeScript(ctx) + (ScriptBuilder() << ScriptOperator::OP_ENDIF);
      case NodeType::THRESH_M: {
          ScriptBuilder script = ScriptBuilder() << k;
          for (const auto& key : keys) {
              script << ctx.ToPKBytes(key);
          }
          return script << keys.size() << (verify ? ScriptOperator::OP_CHECKMULTISIGVERIFY : ScriptOperator::OP_CHECKMULTISIG);
      }
      case NodeType::THRESH: {
          ScriptBuilder script = subs[0].MakeScript(ctx);
          for (size_t i = 1; i < subs.size(); ++i) {
              script = (script + subs[i].MakeScript(ctx)) << ScriptOperator::OP_ADD;
          }
          return script << k << (verify ? ScriptOperator::OP_EQUALVERIFY : ScriptOperator::OP_EQUAL);
      }
  }
  throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
}

//! Internal code for ToString.
std::string Node::MakeString(const MiniScriptConverter& ctx, bool& success, bool wrapped) const {
  switch (nodetype) {
      case NodeType::WRAP_A: return "a" + subs[0].MakeString(ctx, success, true);
      case NodeType::WRAP_S: return "s" + subs[0].MakeString(ctx, success, true);
      case NodeType::WRAP_C: return "c" + subs[0].MakeString(ctx, success, true);
      case NodeType::WRAP_D: return "d" + subs[0].MakeString(ctx, success, true);
      case NodeType::WRAP_V: return "v" + subs[0].MakeString(ctx, success, true);
      case NodeType::WRAP_J: return "j" + subs[0].MakeString(ctx, success, true);
      case NodeType::WRAP_N: return "n" + subs[0].MakeString(ctx, success, true);
      case NodeType::AND_V:
          // t:X is syntactic sugar for and_v(X,1).
          if (subs[1].nodetype == NodeType::JUST_1) return "t" + subs[0].MakeString(ctx, success, true);
          break;
      case NodeType::OR_I:
          if (subs[0].nodetype == NodeType::JUST_0) return "l" + subs[1].MakeString(ctx, success, true);
          if (subs[1].nodetype == NodeType::JUST_0) return "u" + subs[0].MakeString(ctx, success, true);
          break;
      default:
          break;
  }

  std::string ret = wrapped ? ":" : "";

  switch (nodetype) {
      case NodeType::PK: {
          std::string key_str;
          success = ctx.ToString(keys[0], key_str);
          return ret + "pk(" + key_str + ")";
      }
      case NodeType::PK_H: {
          std::string key_str;
          success = ctx.ToString(keys[0], key_str);
          return ret + "pk_h(" + key_str + ")";
      }
      case NodeType::AFTER: return ret + "after(" + std::to_string(k) + ")";
      case NodeType::OLDER: return ret + "older(" + std::to_string(k) + ")";
      case NodeType::HASH256: return ret + "hash256(" + data.GetHex() + ")";
      case NodeType::HASH160: return ret + "hash160(" + data.GetHex() + ")";
      case NodeType::SHA256: return ret + "sha256(" + data.GetHex() + ")";
      case NodeType::RIPEMD160: return ret + "ripemd160(" + data.GetHex() + ")";
      case NodeType::JUST_1: return ret + "1";
      case NodeType::JUST_0: return ret + "0";
      case NodeType::AND_V: return ret + "and_v(" + subs[0].MakeString(ctx, success) + "," + subs[1].MakeString(ctx, success) + ")";
      case NodeType::AND_B: return ret + "and_b(" + subs[0].MakeString(ctx, success) + "," + subs[1].MakeString(ctx, success) + ")";
      case NodeType::OR_B: return ret + "or_b(" + subs[0].MakeString(ctx, success) + "," + subs[1].MakeString(ctx, success) + ")";
      case NodeType::OR_D: return ret + "or_d(" + subs[0].MakeString(ctx, success) + "," + subs[1].MakeString(ctx, success) + ")";
      case NodeType::OR_C: return ret + "or_c(" + subs[0].MakeString(ctx, success) + "," + subs[1].MakeString(ctx, success) + ")";
      case NodeType::OR_I: return ret + "or_i(" + subs[0].MakeString(ctx, success) + "," + subs[1].MakeString(ctx, success) + ")";
      case NodeType::ANDOR:
          // and_n(X,Y) is syntactic sugar for andor(X,Y,0).
          if (subs[2].nodetype == NodeType::JUST_0) return ret + "and_n(" + subs[0].MakeString(ctx, success) + "," + subs[1].MakeString(ctx, success) + ")";
          return ret + "andor(" + subs[0].MakeString(ctx, success) + "," + subs[1].MakeString(ctx, success) + "," + subs[2].MakeString(ctx, success) + ")";
      case NodeType::THRESH_M: {
          auto str = ret + "thresh_m(" + std::to_string(k);
          for (const auto& key : keys) {
              std::string key_str;
              success &= ctx.ToString(key, key_str);
              str += "," + key_str;
          }
          return str + ")";
      }
      case NodeType::THRESH: {
          auto str = ret + "thresh(" + std::to_string(k);
          for (const auto& sub : subs) {
              str += "," + sub.MakeString(ctx, success);
          }
          return str + ")";
      }
      default:
        // assert(false); // Wrappers should have been handled above
        throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
  }
  return "";
}

Ops Node::CalcOps() const {
  switch (nodetype) {
      case NodeType::PK: return {0, 0, 0};
      case NodeType::PK_H: return {3, 0, 0};
      case NodeType::OLDER: return {1, 0, {}};
      case NodeType::AFTER: return {1, 0, {}};
      case NodeType::SHA256: return {4, 0, {}};
      case NodeType::RIPEMD160: return {4, 0, {}};
      case NodeType::HASH256: return {4, 0, {}};
      case NodeType::HASH160: return {4, 0, {}};
      case NodeType::AND_V: return {subs[0].ops.stat + subs[1].ops.stat, subs[0].ops.sat + subs[1].ops.sat, {}};
      case NodeType::AND_B: return {1 + subs[0].ops.stat + subs[1].ops.stat, subs[0].ops.sat + subs[1].ops.sat, subs[0].ops.dsat + subs[1].ops.dsat};
      case NodeType::OR_B: return {1 + subs[0].ops.stat + subs[1].ops.stat, Choose(subs[0].ops.sat + subs[1].ops.dsat, subs[1].ops.sat + subs[0].ops.dsat), subs[0].ops.dsat + subs[1].ops.dsat};
      case NodeType::OR_D: return {3 + subs[0].ops.stat + subs[1].ops.stat, Choose(subs[0].ops.sat, subs[1].ops.sat + subs[0].ops.dsat), subs[0].ops.dsat + subs[1].ops.dsat};
      case NodeType::OR_C: return {2 + subs[0].ops.stat + subs[1].ops.stat, Choose(subs[0].ops.sat, subs[1].ops.sat + subs[0].ops.dsat), {}};
      case NodeType::OR_I: return {3 + subs[0].ops.stat + subs[1].ops.stat, Choose(subs[0].ops.sat, subs[1].ops.sat), Choose(subs[0].ops.dsat, subs[1].ops.dsat)};
      case NodeType::ANDOR: return {3 + subs[0].ops.stat + subs[1].ops.stat + subs[2].ops.stat, Choose(subs[1].ops.sat + subs[0].ops.sat, subs[0].ops.dsat + subs[2].ops.sat), subs[0].ops.dsat + subs[2].ops.dsat};
      case NodeType::THRESH_M: return {1, (uint32_t)keys.size(), (uint32_t)keys.size()};
      case NodeType::WRAP_A: return {2 + subs[0].ops.stat, subs[0].ops.sat, subs[0].ops.dsat};
      case NodeType::WRAP_S: return {1 + subs[0].ops.stat, subs[0].ops.sat, subs[0].ops.dsat};
      case NodeType::WRAP_C: return {1 + subs[0].ops.stat, subs[0].ops.sat, subs[0].ops.dsat};
      case NodeType::WRAP_D: return {3 + subs[0].ops.stat, subs[0].ops.sat, 0};
      case NodeType::WRAP_V: return {subs[0].ops.stat + (subs[0].GetType() << ConvStr("x")), subs[0].ops.sat, {}};
      case NodeType::WRAP_J: return {4 + subs[0].ops.stat, subs[0].ops.sat, 0};
      case NodeType::WRAP_N: return {1 + subs[0].ops.stat, subs[0].ops.sat, subs[0].ops.dsat};
      case NodeType::JUST_1: return {0, 0, {}};
      case NodeType::JUST_0: return {0, {}, 0};
      case NodeType::THRESH: {
          uint32_t stat = 0;
          auto sats = CreateMaxIntList(MaxInt<uint32_t>(0));
          for (const auto& sub : subs) {
              stat += sub.ops.stat + 1;
              auto next_sats = CreateMaxIntList(sats[0] + sub.ops.dsat);
              for (size_t j = 1; j < sats.size(); ++j) next_sats.push_back(Choose(sats[j] + sub.ops.dsat, sats[j - 1] + sub.ops.sat));
              next_sats.push_back(sats[sats.size() - 1] + sub.ops.sat);
              sats = next_sats;
          }
          return {stat, sats[k], sats[0]};
      }
  }
  throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
}

StackSize Node::CalcStackSize() const {
  switch (nodetype) {
      case NodeType::PK: return {1, 1};
      case NodeType::PK_H: return {2, 2};
      case NodeType::OLDER: return {0, {}};
      case NodeType::AFTER: return {0, {}};
      case NodeType::SHA256: return {1, {}};
      case NodeType::RIPEMD160: return {1, {}};
      case NodeType::HASH256: return {1, {}};
      case NodeType::HASH160: return {1, {}};
      case NodeType::ANDOR: return {Choose(subs[0].ss.sat + subs[1].ss.sat, subs[0].ss.dsat + subs[2].ss.sat), subs[0].ss.dsat + subs[2].ss.dsat};
      case NodeType::AND_V: return {subs[0].ss.sat + subs[1].ss.sat, {}};
      case NodeType::AND_B: return {subs[0].ss.sat + subs[1].ss.sat, subs[0].ss.dsat + subs[1].ss.dsat};
      case NodeType::OR_B: return {Choose(subs[0].ss.dsat + subs[1].ss.sat, subs[0].ss.sat + subs[1].ss.dsat), subs[0].ss.dsat + subs[1].ss.dsat};
      case NodeType::OR_C: return {Choose(subs[0].ss.sat, subs[0].ss.dsat + subs[1].ss.sat), {}};
      case NodeType::OR_D: return {Choose(subs[0].ss.sat, subs[0].ss.dsat + subs[1].ss.sat), subs[0].ss.dsat + subs[1].ss.dsat};
      case NodeType::OR_I: return {Choose(subs[0].ss.sat + 1, subs[1].ss.sat + 1), Choose(subs[0].ss.dsat + 1, subs[1].ss.dsat + 1)};
      case NodeType::THRESH_M: return {(uint32_t)keys.size() + 1, (uint32_t)keys.size() + 1};
      case NodeType::WRAP_A: return subs[0].ss;
      case NodeType::WRAP_S: return subs[0].ss;
      case NodeType::WRAP_C: return subs[0].ss;
      case NodeType::WRAP_D: return {1 + subs[0].ss.sat, 1};
      case NodeType::WRAP_V: return {subs[0].ss.sat, {}};
      case NodeType::WRAP_J: return {subs[0].ss.sat, 1};
      case NodeType::WRAP_N: return subs[0].ss;
      case NodeType::JUST_1: return {0, {}};
      case NodeType::JUST_0: return {{}, 0};
      case NodeType::THRESH: {
          auto sats = CreateMaxIntList(MaxInt<uint32_t>(0));
          for (const auto& sub : subs) {
              auto next_sats = CreateMaxIntList(sats[0] + sub.ss.dsat);
              for (size_t j = 1; j < sats.size(); ++j) next_sats.push_back(Choose(sats[j] + sub.ss.dsat, sats[j - 1] + sub.ss.sat));
              next_sats.push_back(sats[sats.size() - 1] + sub.ss.sat);
              sats = next_sats;
          }
          return {sats[k], sats[0]};
      }
  }
  throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
}

InputResult Node::ProduceInput(const MiniScriptConverter& ctx, bool nonmal) const {
  auto ret = ProduceInputHelper(ctx, nonmal);
  // Do a consistency check between the satisfaction code and the type checker
  // (the actual satisfaction code in ProduceInputHelper does not use GetType)
  if (GetType() << ConvStr("z") && ret.nsat.available != Availability::NO) {
    // assert(ret.nsat.stack.size() == 0);
    if (!(ret.nsat.stack.size() == 0)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
  }
  if (GetType() << ConvStr("z") && ret.sat.available != Availability::NO) {
    // assert(ret.sat.stack.size() == 0);
    if (!(ret.nsat.stack.size() == 0)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
  }
  if (GetType() << ConvStr("o") && ret.nsat.available != Availability::NO) {
    // assert(ret.nsat.stack.size() == 1);
    if (!(ret.nsat.stack.size() == 1)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
  }
  if (GetType() << ConvStr("o") && ret.sat.available != Availability::NO) {
    // assert(ret.sat.stack.size() == 1);
    if (!(ret.nsat.stack.size() == 1)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
  }
  if (GetType() << ConvStr("n") && ret.sat.available != Availability::NO) {
    // assert(ret.sat.stack.back().size() != 0);
    if (!(ret.sat.stack.back().size() != 0)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
  }
  if (GetType() << ConvStr("d")) {
    // assert(ret.nsat.available != Availability::NO);
    if (!(ret.nsat.available != Availability::NO)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
  }
  if (GetType() << ConvStr("f") && ret.nsat.available != Availability::NO) {
    // assert(ret.nsat.has_sig);
    if (!(ret.nsat.has_sig)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
  }
  if (GetType() << ConvStr("s") && ret.sat.available != Availability::NO) {
    // assert(ret.sat.has_sig);
    if (!(ret.sat.has_sig)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
  }
  if (nonmal) {
    if (GetType() << ConvStr("d")) {
      // assert(!ret.nsat.has_sig);
      if (!(!ret.nsat.has_sig)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    }
    if (GetType() << ConvStr("d") && !ret.nsat.malleable) {
      // assert(!ret.nsat.non_canon);
      if (!(!ret.nsat.non_canon)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    }
    if (GetType() << ConvStr("e")) {
      // assert(!ret.nsat.malleable);
      if (!(!ret.nsat.malleable)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    }
    if (GetType() << ConvStr("m") && ret.sat.available != Availability::NO) {
      // assert(!ret.sat.malleable);
      if (!(!ret.sat.malleable)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    }
    if (ret.sat.available != Availability::NO && !ret.sat.malleable) {
      // assert(!ret.sat.non_canon);
      if (!(!ret.sat.non_canon)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    }
  }
  return ret;
}

InputResult Node::ProduceInputHelper(const MiniScriptConverter& ctx, bool nonmal) const {
  const auto INVALID = InputStack().Available(Availability::NO);
#if 0
  const auto ZERO = InputStack(std::vector<uint8_t>());
  const auto ZERO32 = InputStack(std::vector<uint8_t>(32, 0)).Malleable();
  const auto ONE = InputStack(std::vector<uint8_t>{(uint8_t)1});
  const auto EMPTY = InputStack();
  const auto MALLEABLE_EMPTY = InputStack().Malleable();

  switch (nodetype) {
      case NodeType::PK: {
          std::vector<uint8_t> sig;
          Availability avail = ctx.Sign(keys[0], sig);
          return InputResult(ZERO, InputStack(sig).WithSig().Available(avail));
      }
      case NodeType::PK_H: {
          std::vector<uint8_t> key = ctx.ToPKBytes(keys[0]), sig;
          Availability avail = ctx.Sign(keys[0], sig);
          return InputResult(ZERO + InputStack(key), (InputStack(sig).WithSig() + InputStack(key)).Available(avail));
      }
      case NodeType::THRESH_M: {
          std::vector<InputStack> sats = {ZERO};
          for (size_t i = 0; i < keys.size(); ++i) {
              std::vector<uint8_t> sig;
              Availability avail = ctx.Sign(keys[i], sig);
              auto sat = InputStack(sig).WithSig().Available(avail);
              std::vector<InputStack> next_sats;
              next_sats.push_back(sats[0]);
              for (size_t j = 1; j < sats.size(); ++j) next_sats.push_back(Choose(sats[j], sats[j - 1] + sat, nonmal));
              next_sats.push_back(sats[sats.size() - 1] + sat);
              sats = next_sats;
          }
          InputStack nsat = ZERO;
          for (size_t i = 0; i < k; ++i) nsat = nsat + ZERO;
          return InputResult(nsat, sats[k]);
      }
      case NodeType::THRESH: {
          std::vector<InputStack> sats = {EMPTY};
          for (size_t i = 0; i < subs.size(); ++i) {
              auto res = subs[subs.size() - i - 1].ProduceInput(ctx, nonmal);
              std::vector<InputStack> next_sats;
              next_sats.push_back(sats[0] + res.nsat);
              for (size_t j = 1; j < sats.size(); ++j) next_sats.push_back(Choose(sats[j] + res.nsat, sats[j - 1] + res.sat, nonmal));
              next_sats.push_back(sats[sats.size() - 1] + res.sat);
              sats = next_sats;
          }
          InputStack nsat = INVALID;
          for (size_t i = 0; i < sats.size(); ++i) {
              if (i != k) nsat = Choose(nsat, sats[i], nonmal);
          }
          return InputResult(nsat, sats[k]);
      }
      case NodeType::OLDER: {
          return InputResult(INVALID, ctx.CheckOlder(k) ? EMPTY : INVALID);
      }
      case NodeType::AFTER: {
          return InputResult(INVALID, ctx.CheckAfter(k) ? EMPTY : INVALID);
      }
      case NodeType::SHA256: {
          std::vector<uint8_t> preimage;
          Availability avail = ctx.SatSHA256(data, preimage);
          return InputResult(ZERO32, InputStack(preimage).Available(avail));
      }
      case NodeType::RIPEMD160: {
          std::vector<uint8_t> preimage;
          Availability avail = ctx.SatRIPEMD160(data, preimage);
          return InputResult(ZERO32, InputStack(preimage).Available(avail));
      }
      case NodeType::HASH256: {
          std::vector<uint8_t> preimage;
          Availability avail = ctx.SatHASH256(data, preimage);
          return InputResult(ZERO32, InputStack(preimage).Available(avail));
      }
      case NodeType::HASH160: {
          std::vector<uint8_t> preimage;
          Availability avail = ctx.SatHASH160(data, preimage);
          return InputResult(ZERO32, InputStack(preimage).Available(avail));
      }
      case NodeType::AND_V: {
          auto x = subs[0].ProduceInput(ctx, nonmal), y = subs[1].ProduceInput(ctx, nonmal);
          return InputResult((y.nsat + x.sat).NonCanon(), y.sat + x.sat);
      }
      case NodeType::AND_B: {
          auto x = subs[0].ProduceInput(ctx, nonmal), y = subs[1].ProduceInput(ctx, nonmal);
          return InputResult(Choose(Choose(y.nsat + x.nsat, (y.sat + x.nsat).NonCanon(), nonmal), (y.nsat + x.sat).NonCanon(), nonmal), y.sat + x.sat);
      }
      case NodeType::OR_B: {
          auto x = subs[0].ProduceInput(ctx, nonmal), z = subs[1].ProduceInput(ctx, nonmal);
          return InputResult(z.nsat + x.nsat, Choose(Choose(z.nsat + x.sat, z.sat + x.nsat, nonmal), (z.sat + x.sat).NonCanon(), nonmal));
      }
      case NodeType::OR_C: {
          auto x = subs[0].ProduceInput(ctx, nonmal), z = subs[1].ProduceInput(ctx, nonmal);
          return InputResult(INVALID, Choose(x.sat, z.sat + x.nsat, nonmal));
      }
      case NodeType::OR_D: {
          auto x = subs[0].ProduceInput(ctx, nonmal), z = subs[1].ProduceInput(ctx, nonmal);
          auto nsat = z.nsat + x.nsat, sat_l = x.sat, sat_r = z.sat + x.nsat;
          return InputResult(z.nsat + x.nsat, Choose(x.sat, z.sat + x.nsat, nonmal));
      }
      case NodeType::OR_I: {
          auto x = subs[0].ProduceInput(ctx, nonmal), z = subs[1].ProduceInput(ctx, nonmal);
          return InputResult(Choose(x.nsat + ONE, z.nsat + ZERO, nonmal), Choose(x.sat + ONE, z.sat + ZERO, nonmal));
      }
      case NodeType::ANDOR: {
          auto x = subs[0].ProduceInput(ctx, nonmal), y = subs[1].ProduceInput(ctx, nonmal), z = subs[2].ProduceInput(ctx, nonmal);
          return InputResult(Choose((y.nsat + x.sat).NonCanon(), z.nsat + x.nsat, nonmal), Choose(y.sat + x.sat, z.sat + x.nsat, nonmal));
      }
      case NodeType::WRAP_A:
      case NodeType::WRAP_S:
      case NodeType::WRAP_C:
      case NodeType::WRAP_N:
          return subs[0].ProduceInput(ctx, nonmal);
      case NodeType::WRAP_D: {
          auto x = subs[0].ProduceInput(ctx, nonmal);
          return InputResult(ZERO, x.sat + ONE);
      }
      case NodeType::WRAP_J: {
          auto x = subs[0].ProduceInput(ctx, nonmal);
          // If a dissatisfaction with a nonzero top stack element exists, an alternative dissatisfaction exists.
          // As the dissatisfaction logic currently doesn't keep track of this nonzeroness property, and thus even
          // if a dissatisfaction with a top zero element is found, we don't know whether another one with a
          // nonzero top stack element exists. Make the conservative assumption that whenever the subexpression is weakly
          // dissatisfiable, this alternative dissatisfaction exists and leads to malleability.
          return InputResult(InputStack(ZERO).Malleable(x.nsat.available != Availability::NO && !x.nsat.has_sig), x.sat);
      }
      case NodeType::WRAP_V: {
          auto x = subs[0].ProduceInput(ctx, nonmal);
          return InputResult(INVALID, x.sat);
      }
      case NodeType::JUST_0: return InputResult(EMPTY, INVALID);
      case NodeType::JUST_1: return InputResult(INVALID, EMPTY);
  }
  throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
#endif
  return InputResult(INVALID, INVALID);
}



//! Convert this miniscript to its textual descriptor notation.
bool Node::ToString(const MiniScriptConverter& ctx, std::string& out) const {
  bool ret = true;
  out = MakeString(ctx, ret);
  if (!ret) out = "";
  return ret;
}

Availability Node::Satisfy(const MiniScriptConverter& ctx,
      std::vector<std::vector<uint8_t>>& stack, bool nonmalleable) const {
  auto ret = ProduceInput(ctx, nonmalleable);
  if (nonmalleable && (ret.sat.malleable || !ret.sat.has_sig)) return Availability::NO;
  stack = ret.sat.stack;
  return ret.sat.available;
}

//! Equality testing.
bool Node::operator==(const Node& arg) const
{
    if (nodetype != arg.nodetype) return false;
    if (k != arg.k) return false;
    if (!data.Equals(arg.data)) return false;
    if (keys.size() != arg.keys.size()) return false;
    //if (keys != arg.keys) return false;
    for (size_t i=0; i<keys.size(); ++i)
      if(!keys[i].Equals(arg.keys[i])) return false;

    if (subs.size() != arg.subs.size()) return false;
    for (size_t i = 0; i < subs.size(); ++i) {
        if (!(subs[i] == arg.subs[i])) return false;
    }
    // assert(scriptlen == arg.scriptlen);
    // assert(typ == arg.typ);
    if (!((scriptlen == arg.scriptlen) && (typ == arg.typ)))
        throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    return true;
}

Node& Node::operator=(const Node& node_data) {
  nodetype = node_data.nodetype;
  k = node_data.k;
  ops = node_data.ops;
  ss = node_data.ss;
  typ = node_data.typ;
  scriptlen = node_data.scriptlen;
  converter = node_data.converter;
  keys = node_data.keys;
  data = node_data.data;
  subs = node_data.subs;
  return *this;
}



//------------------------------------------------------

//! Public keys in text form are their usual hex notation (no xpubs, ...).
bool MiniScriptConverter::ToString(const Pubkey& key, std::string& ret) const {
  ret = key.GetHex();
  return true;
}
bool MiniScriptConverter::ToString(const ByteData& key, std::string& ret) const {
  ret = key.GetHex();
  return true;
}

//! Convert a public key to bytes.
std::vector<uint8_t> MiniScriptConverter::ToPKBytes(const Pubkey& key) const {
  return key.GetData().GetBytes();
}
ByteData MiniScriptConverter::ToPKBytes(const ByteData& key) const {
  return key;
}

//! Convert a public key to its Hash160 bytes (precomputed).
std::vector<uint8_t> MiniScriptConverter::ToPKHBytes(const Pubkey& key) const
{
#if 0
  auto it = g_testdata->pkhashes.find(key);
  assert(it != g_testdata->pkhashes.end());
  return {it->second.begin(), it->second.end()};
#else
  return key.GetData().GetBytes();
#endif
}

ByteData MiniScriptConverter::ToPKHBytes(const ByteData& key) const
{
  return key;
}

//! Parse a public key from a range of hex characters.
bool MiniScriptConverter::FromString(std::string str, ByteData& key) const {
  auto bytes = ParseHex(str);
  // key.Set(bytes.begin(), bytes.end());
  if (bytes.size() == 0) {
    if (!str.empty()) {
      // name text
      // set dummy pubkey data
      key = ByteData("030000000000000000000000000000000000000000000000000000000000000000");
      return true;
    }
    return false;
  }
  Pubkey pubkey = Pubkey(ByteData(bytes));
  key = pubkey.GetData();
  return pubkey.IsValid();
}

bool MiniScriptConverter::FromPKBytes(const std::vector<uint8_t>& byte_array, ByteData& key) const {
  // key.Set(first, last);
  // key.Set(bytes.begin(), bytes.end());
  if (byte_array.size() == 0) {
    return false;
  }
  Pubkey pubkey = Pubkey(ByteData(byte_array));
  key = pubkey.GetData();
  return pubkey.IsValid();
}

bool MiniScriptConverter::FromPKHBytes(const std::vector<uint8_t>& byte_array, ByteData& key) const {
  if (byte_array.size() != 20) {
    throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
  }
  key = ByteData(byte_array);
  return true;
}

Type SanitizeType(Type e) {
    int num_types = (e << ConvStr("K")) + (e << ConvStr("V")) + (e << ConvStr("B")) + (e << ConvStr("W"));
    if (num_types == 0) return Type(0); // No valid type, don't care about the rest
    // assert(num_types == 1); // K, V, B, W all conflict with each other
    if (num_types != 1) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    bool ok = // Work around a GCC 4.8 bug that breaks user-defined literals in macro calls.
        (!(e << ConvStr("z")) || !(e << ConvStr("o"))) && // z conflicts with o
        (!(e << ConvStr("n")) || !(e << ConvStr("z"))) && // n conflicts with z
        (!(e << ConvStr("V")) || !(e << ConvStr("d"))) && // V conflicts with d
        (!(e << ConvStr("K")) ||  (e << ConvStr("u"))) && // K implies u
        (!(e << ConvStr("V")) || !(e << ConvStr("u"))) && // V conflicts with u
        (!(e << ConvStr("e")) || !(e << ConvStr("f"))) && // e conflicts with f
        (!(e << ConvStr("e")) ||  (e << ConvStr("d"))) && // e implies d
        (!(e << ConvStr("V")) || !(e << ConvStr("e"))) && // V conflicts with e
        (!(e << ConvStr("d")) || !(e << ConvStr("f"))) && // d conflicts with f
        (!(e << ConvStr("V")) ||  (e << ConvStr("f"))) && // V implies f
        (!(e << ConvStr("K")) ||  (e << ConvStr("s"))) && // K implies s
        (!(e << ConvStr("z")) ||  (e << ConvStr("m"))); // z implies m
    if (!ok) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    return e;
}

Type ComputeType(NodeType nodetype, Type x, Type y, Type z, const std::vector<Type>& sub_types, uint32_t k, size_t data_size, size_t n_subs, size_t n_keys) {
    // Sanity check on data
    if (nodetype == NodeType::SHA256 || nodetype == NodeType::HASH256) {
        // assert(data_size == 32);
        if (!(data_size == 32)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    } else if (nodetype == NodeType::RIPEMD160 || nodetype == NodeType::HASH160) {
        // assert(data_size == 20);
        if (!(data_size == 20)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__) + ", data_size=" + std::to_string(data_size));
    } else {
        // assert(data_size == 0);
        if (!(data_size == 0)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    }
    // Sanity check on k
    if (nodetype == NodeType::OLDER || nodetype == NodeType::AFTER) {
        // assert(k >= 1 && k < 0x80000000UL);
        if (!(k >= 1 && k < 0x80000000UL)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    } else if (nodetype == NodeType::THRESH_M) {
        // assert(k >= 1 && k <= n_keys);
        if (!(k >= 1 && k <= n_keys)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    } else if (nodetype == NodeType::THRESH) {
        // assert(k > 1 && k < n_subs);
        if (!(k > 1 && k < n_subs)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    } else {
        // assert(k == 0);
        if (!(k == 0)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    }
    // Sanity check on subs
    if (nodetype == NodeType::AND_V || nodetype == NodeType::AND_B || nodetype == NodeType::OR_B ||
        nodetype == NodeType::OR_C || nodetype == NodeType::OR_I || nodetype == NodeType::OR_D) {
        // assert(n_subs == 2);
        if (!(n_subs == 2)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    } else if (nodetype == NodeType::ANDOR) {
        // assert(n_subs == 3);
        if (!(n_subs == 3)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    } else if (nodetype == NodeType::WRAP_A || nodetype == NodeType::WRAP_S || nodetype == NodeType::WRAP_C ||
               nodetype == NodeType::WRAP_D || nodetype == NodeType::WRAP_V || nodetype == NodeType::WRAP_J ||
               nodetype == NodeType::WRAP_N) {
        // assert(n_subs == 1);
        if (!(n_subs == 1)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    } else if (nodetype != NodeType::THRESH) {
        // assert(n_subs == 0);
        if (!(n_subs == 0)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    }
    // Sanity check on keys
    if (nodetype == NodeType::PK || nodetype == NodeType::PK_H) {
        // assert(n_keys == 1);
        if (!(n_keys == 1)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    } else if (nodetype == NodeType::THRESH_M) {
        // assert(n_keys >= 1 && n_keys <= 20);
        if (!(n_keys >= 1 && n_keys <= 20)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    } else {
        // assert(n_keys == 0);
        if (!(n_keys == 0)) throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    }

    // Below is the per-nodetype logic for computing the expression types.
    // It heavily relies on Type's << operator (where "X << a_mst" means
    // "X has all properties listed in a").
    switch (nodetype) {
        case NodeType::PK: return ConvStr("Konudemsx");
        case NodeType::PK_H: return ConvStr("Knudemsx");
        case NodeType::OLDER: return ConvStr("Bzfmx");
        case NodeType::AFTER: return ConvStr("Bzfmx");
        case NodeType::SHA256: return ConvStr("Bonudm");
        case NodeType::RIPEMD160: return ConvStr("Bonudm");
        case NodeType::HASH256: return ConvStr("Bonudm");
        case NodeType::HASH160: return ConvStr("Bonudm");
        case NodeType::JUST_1: return ConvStr("Bzufmx");
        case NodeType::JUST_0: return ConvStr("Bzudemsx");
        case NodeType::WRAP_A: return
            ConvStr("W").If(x << ConvStr("B")) | // W=B_x
            (x & ConvStr("udfems")) | // u=u_x, d=d_x, f=f_x, e=e_x, m=m_x, s=s_x
            ConvStr("x"); // x
        case NodeType::WRAP_S: return
            ConvStr("W").If(x << ConvStr("Bo")) | // W=B_x*o_x
            (x & ConvStr("udfemsx")); // u=u_x, d=d_x, f=f_x, e=e_x, m=m_x, s=s_x, x=x_x
        case NodeType::WRAP_C: return
            ConvStr("B").If(x << ConvStr("K")) | // B=K_x
             (x & ConvStr("ondfem")) | // o=o_x, n=n_x, d=d_x, f=f_x, e=e_x, m=m_x
             ConvStr("us"); // u, s
        case NodeType::WRAP_D: return
            ConvStr("B").If(x << ConvStr("Vz")) | // B=V_x*z_x
            ConvStr("o").If(x << ConvStr("z")) | // o=z_x
            ConvStr("e").If(x << ConvStr("f")) | // e=f_x
            (x & ConvStr("ms")) | // m=m_x, s=s_x
            ConvStr("nudx"); // n, u, d, x
        case NodeType::WRAP_V: return
            ConvStr("V").If(x << ConvStr("B")) | // V=B_x
            (x & ConvStr("zonms")) | // z=z_x, o=o_x, n=n_x, m=m_x, s=s_x
            ConvStr("fx"); // f, x
        case NodeType::WRAP_J: return
            ConvStr("B").If(x << ConvStr("Bn")) | // B=B_x*n_x
            ConvStr("e").If(x << ConvStr("f")) | // e=f_x
            (x & ConvStr("oums")) | // o=o_x, u=u_x, m=m_x, s=s_x
            ConvStr("ndx"); // n, d, x
        case NodeType::WRAP_N: return
            (x & ConvStr("Bzondfems")) | // B=B_x, z=z_x, o=o_x, n=n_x, d=d_x, f=f_x, e=e_x, m=m_x, s=s_x
            ConvStr("ux"); // u, x
        case NodeType::AND_V: return
            (y & ConvStr("KVB")).If(x << ConvStr("V")) | // B=V_x*B_y, V=V_x*V_y, K=V_x*K_y
            (x & ConvStr("n")) | (y & ConvStr("n")).If(x << ConvStr("z")) | // n=n_x+z_x*n_y
            ((x | y) & ConvStr("o")).If((x | y) << ConvStr("z")) | // o=o_x*z_y+z_x*o_y
            (x & y & ConvStr("dmz")) | // d=d_x*d_y, m=m_x*m_y, z=z_x*z_y
            ((x | y) & ConvStr("s")) | // s=s_x+s_y
            ConvStr("f").If((y << ConvStr("f")) || (x << ConvStr("s"))) | // f=f_y+s_x
            (y & ConvStr("ux")); // u=u_y, x=x_y
        case NodeType::AND_B: return
            (x & ConvStr("B")).If(y << ConvStr("W")) | // B=B_x*W_y
            ((x | y) & ConvStr("o")).If((x | y) << ConvStr("z")) | // o=o_x*z_y+z_x*o_y
            (x & ConvStr("n")) | (y & ConvStr("n")).If(x << ConvStr("z")) | // n=n_x+z_x*n_y
            (x & y & ConvStr("e")).If((x & y) << ConvStr("s")) | // e=e_x*e_y*s_x*s_y
            (x & y & ConvStr("dzm")) | // d=d_x*d_y, z=z_x*z_y, m=m_x*m_y
            ConvStr("f").If(((x & y) << ConvStr("f")) || (x << ConvStr("sf")) || (y << ConvStr("sf"))) | // f=f_x*f_y + f_x*s_x + f_y*s_y
            ((x | y) & ConvStr("s")) | // s=s_x+s_y
            ConvStr("ux"); // u, x
        case NodeType::OR_B: return
            ConvStr("B").If(x << ConvStr("Bd") && y << ConvStr("Wd")) | // B=B_x*d_x*W_x*d_y
            ((x | y) & ConvStr("o")).If((x | y) << ConvStr("z")) | // o=o_x*z_y+z_x*o_y
            (x & y & ConvStr("m")).If((x | y) << ConvStr("s") && (x & y) << ConvStr("e")) | // m=m_x*m_y*e_x*e_y*(s_x+s_y)
            (x & y & ConvStr("zse")) | // z=z_x*z_y, s=s_x*s_y, e=e_x*e_y
            ConvStr("dux"); // d, u, x
        case NodeType::OR_D: return
            (y & ConvStr("B")).If(x << ConvStr("Bdu")) | // B=B_y*B_x*d_x*u_x
            (x & ConvStr("o")).If(y << ConvStr("z")) | // o=o_x*z_y
            (x & y & ConvStr("m")).If(x << ConvStr("e") && (x | y) << ConvStr("s")) | // m=m_x*m_y*e_x*(s_x+s_y)
            (x & y & ConvStr("zes")) | // z=z_x*z_y, e=e_x*e_y, s=s_x*s_y
            (y & ConvStr("ufd")) | // u=u_y, f=f_y, d=d_y
            ConvStr("x"); // x
        case NodeType::OR_C: return
            (y & ConvStr("V")).If(x << ConvStr("Bdu")) | // V=V_y*B_x*u_x*d_x
            (x & ConvStr("o")).If(y << ConvStr("z")) | // o=o_x*z_y
            (x & y & ConvStr("m")).If(x << ConvStr("e") && (x | y) << ConvStr("s")) | // m=m_x*m_y*e_x*(s_x*s_y)
            (x & y & ConvStr("zs")) | // z=z_x*z_y, s=s_x*s_y
            ConvStr("fx"); // f, x
        case NodeType::OR_I: return
            (x & y & ConvStr("VBKufs")) | // V=V_x*V_y, B=B_x*B_y, K=K_x*K_y, u=u_x*u_y, f=f_x*f_y, s=s_x*s_y
            ConvStr("o").If((x & y) << ConvStr("z")) | // o=z_x*z_y
            ((x | y) & ConvStr("e")).If((x | y) << ConvStr("f")) | // e=e_x*f_y+f_x*e_y
            (x & y & ConvStr("m")).If((x | y) << ConvStr("s")) | // m=m_x*m_y*(s_x+s_y)
            ((x | y) & ConvStr("d")) | // d=d_x+d_y
            ConvStr("x"); // x
        case NodeType::ANDOR: return
            (y & z & ConvStr("BKV")).If(x << ConvStr("Bdu")) | // B=B_x*d_x*u_x*B_y*B_z, K=B_x*d_x*u_x*K_y*K_z, V=B_x*d_x*u_x*V_y*V_z
            (x & y & z & ConvStr("z")) | // z=z_x*z_y*z_z
            ((x | (y & z)) & ConvStr("o")).If((x | (y & z)) << ConvStr("z")) | // o=o_x*z_y*z_z+z_x+o_y*o_z
            (y & z & ConvStr("u")) | // f=f_y*f_z, u=u_y*u_z
            (z & ConvStr("f")).If((x << ConvStr("s")) || (y << ConvStr("f"))) |
            (z & ConvStr("d")) | // d=d_x
            (x & z & ConvStr("e")).If(x << ConvStr("s") || y << ConvStr("f")) | // e=e_x*e_z*(s_x+s_y)
            (x & y & z & ConvStr("m")).If(x << ConvStr("e") && (x | y | z) << ConvStr("s")) | // m=m_x*m_y*m_z*e_x*(s_x+s_y+s_z)
            (z & (x | y) & ConvStr("s")) | // s=s_z*(s_x+s_y)
            ConvStr("x"); // x
        case NodeType::THRESH_M: return ConvStr("Bnudems");
        case NodeType::THRESH: {
            bool all_e = true;
            bool all_m = true;
            uint32_t args = 0;
            uint32_t num_s = 0;
            for (size_t i = 0; i < sub_types.size(); ++i) {
                Type t = sub_types[i];
                if (!(t << (i ? ConvStr("Wdu") : ConvStr("Bdu")))) return Type(0); // Require Bdu, Wdu, Wdu, ...
                if (!(t << ConvStr("e"))) all_e = false;
                if (!(t << ConvStr("m"))) all_m = false;
                if (t << ConvStr("s")) num_s += 1;
                args += (t << ConvStr("z")) ? 0 : (t << ConvStr("o")) ? 1 : 2;
            }
            return ConvStr("Bdu") |
                   ConvStr("z").If(args == 0) | // z=all z
                   ConvStr("o").If(args == 1) | // o=all z except one o
                   ConvStr("e").If(all_e && num_s == n_subs) | // e=all e and all s
                   ConvStr("m").If(all_e && all_m && num_s >= n_subs - k) | // m=all e, >=(n-k) s
                   ConvStr("s").If(num_s >= n_subs - k + 1); // s= >=(n-k+1) s
            }
    }
    throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    // return Type(0);
}

size_t ComputeScriptLen(NodeType nodetype, Type sub0typ, size_t subsize, uint32_t k, size_t n_subs, size_t n_keys) {
    switch (nodetype) {
        case NodeType::PK: return subsize + 34;
        case NodeType::PK_H: return subsize + 3 + 21;
        case NodeType::OLDER:
        case NodeType::AFTER: {
          ScriptElement elem(static_cast<int64_t>(k));
          return subsize + 1 + elem.GetData().GetDataSize();
          // Script script = ScriptBuilder().AppendData(static_cast<int64_t>(k)).Build();
          // return subsize + 1 + script.GetData().GetDataSize();
        }
        case NodeType::HASH256: return subsize + 4 + 2 + 33;
        case NodeType::HASH160: return subsize + 4 + 2 + 21;
        case NodeType::SHA256: return subsize + 4 + 2 + 33;
        case NodeType::RIPEMD160: return subsize + 4 + 2 + 21;
        case NodeType::WRAP_A: return subsize + 2;
        case NodeType::WRAP_S: return subsize + 1;
        case NodeType::WRAP_C: return subsize + 1;
        case NodeType::WRAP_D: return subsize + 3;
        case NodeType::WRAP_V: return subsize + (sub0typ << ConvStr("x"));
        case NodeType::WRAP_J: return subsize + 4;
        case NodeType::WRAP_N: return subsize + 1;
        case NodeType::JUST_1: return 1;
        case NodeType::JUST_0: return 1;
        case NodeType::AND_V: return subsize;
        case NodeType::AND_B: return subsize + 1;
        case NodeType::OR_B: return subsize + 1;
        case NodeType::OR_D: return subsize + 3;
        case NodeType::OR_C: return subsize + 2;
        case NodeType::OR_I: return subsize + 3;
        case NodeType::ANDOR: return subsize + 3;
        case NodeType::THRESH: return subsize + n_subs + 1;
        case NodeType::THRESH_M: return subsize + 3 + (n_keys > 16) + (k > 16) + 34 * n_keys;
    }
    throw cfd::core::CfdException(CfdError::kCfdIllegalStateError, std::string(__FUNCTION__) + " error. line=" + std::to_string(__LINE__));
    //return 0;
}

InputStack& InputStack::Available(Availability avail) {
    available = avail;
    if (avail == Availability::NO) {
        stack.clear();
        size = std::numeric_limits<size_t>::max();
        has_sig = false;
        malleable = false;
        non_canon = false;
    }
    return *this;
}

InputStack& InputStack::WithSig() {
    has_sig = true;
    return *this;
}

InputStack& InputStack::NonCanon() {
    non_canon = true;
    return *this;
}

InputStack& InputStack::Malleable(bool x) {
    malleable = x;
    return *this;
}

InputStack operator+(InputStack a, InputStack b) {
    a.stack.reserve(a.stack.size() + b.stack.size());
    for (const auto& arg : b.stack) {
        a.stack.push_back(arg);
    }
    // a.stack = Cat(a.stack, b.stack);
    a.size += b.size;
    a.has_sig |= b.has_sig;
    a.malleable |= b.malleable;
    a.non_canon |= b.non_canon;
    if (a.available == Availability::NO || b.available == Availability::NO) {
        a.Available(Availability::NO);
    } else if (a.available == Availability::MAYBE || b.available == Availability::MAYBE) {
        a.Available(Availability::MAYBE);
    }
    return a;
}

InputStack Choose(InputStack a, InputStack b, bool nonmalleable) {
    // If only one (or neither) is valid, pick the other one.
    if (a.available == Availability::NO) return b;
    if (b.available == Availability::NO) return a;
    // If both are valid, they must be distinct.
    if (nonmalleable) {
        // If both options are weak, any result is fine; it just needs the malleable marker.
        if (!a.has_sig && !b.has_sig) return a.Malleable();
        // If one option is weak, we must pick that one.
        if (!a.has_sig) return a;
        if (!b.has_sig) return b;
        // If both options are strong, prefer the canonical one.
        if (b.non_canon) return a;
        if (a.non_canon) return b;
        // If both options are strong and canonical, prefer the nonmalleable one.
        if (b.malleable) return a;
        if (a.malleable) return b;
    }
    // Pick the smaller between YESes and the bigger between MAYBEs. Prefer YES over MAYBE.
    if (a.available == Availability::YES && b.available == Availability::YES) {
        return std::move(a.size <= b.size ? a : b);
    } else if (a.available == Availability::MAYBE && b.available == Availability::MAYBE) {
        return std::move(a.size >= b.size ? a : b);
    } else if (a.available == Availability::YES) {
        return a;
    } else {
        return b;
    }
}

bool DecomposeScript(const Script& script, std::vector<std::pair<ScriptOperator, std::vector<uint8_t>>>& out)
{
  out.clear();
  std::vector<ScriptElement> list = script.GetElementList();
  for (size_t idx=0; idx<list.size(); ++idx) {
    ScriptElement element = list[idx];
    ScriptOperator opcode = element.GetOpCode();
    if (opcode == ScriptOperator::OP_CHECKSIGVERIFY) {
        // Decompose OP_CHECKSIGVERIFY into OP_CHECKSIG OP_VERIFY
        out.emplace_back(ScriptOperator::OP_CHECKSIG, std::vector<uint8_t>());
        opcode = ScriptOperator::OP_VERIFY;
    } else if (opcode == ScriptOperator::OP_CHECKMULTISIGVERIFY) {
        // Decompose OP_CHECKMULTISIGVERIFY into OP_CHECKMULTISIG OP_VERIFY
        out.emplace_back(ScriptOperator::OP_CHECKMULTISIG, std::vector<uint8_t>());
        opcode = ScriptOperator::OP_VERIFY;
    } else if (opcode == ScriptOperator::OP_EQUALVERIFY) {
        // Decompose OP_EQUALVERIFY into OP_EQUAL OP_VERIFY
        out.emplace_back(ScriptOperator::OP_EQUAL, std::vector<uint8_t>());
        opcode = ScriptOperator::OP_VERIFY;
    }
    if (element.IsOpCode() && element.IsNumber()) {
      std::vector<uint8_t> push_data;
      push_data.push_back(static_cast<uint8_t>(element.GetNumber()));
      out.emplace_back(opcode, push_data);
    } else if (element.IsOpCode()) {
      if ((idx + 1) < list.size()) {
        // do nothing
      }
      out.emplace_back(opcode, std::vector<uint8_t>());
    } else {
      // バイナリの場合はサイズ等をセット
      std::vector<uint8_t> byte_array = element.GetData().GetBytes();
      opcode = ScriptOperator(static_cast<ScriptType>(byte_array[0]));
      // byte_array.erase(byte_array.begin());
      if (element.IsBinary()) {
        out.emplace_back(opcode, element.GetBinaryData().GetBytes());
      } else {
        byte_array.erase(byte_array.begin());
        out.emplace_back(opcode, byte_array);
      }
    }
  }
  std::reverse(out.begin(), out.end());
  return true;
}

bool ParseScriptNumber(const std::pair<ScriptOperator, std::vector<uint8_t>>& in, int64_t& k) {
  if (in.first == ScriptOperator::OP_0) {
    k = 0;
    return true;
  }
  if (!in.second.empty()) {
    try {
      ScriptElement elem(ByteData(in.second));
      return elem.ConvertBinaryToNumber(&k);
      // k = CScriptNum(in.second, true).GetInt64();
      // return true;
    } catch(const std::exception&) {}
  }
  return false;
}

} // namespace core
} // namespace cfd
