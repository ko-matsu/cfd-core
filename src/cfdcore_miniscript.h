// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// miniscript: https://github.com/sipa/miniscript

#ifndef BITCOIN_SCRIPT_MINISCRIPT_H
#define BITCOIN_SCRIPT_MINISCRIPT_H

#include <algorithm>
#include <numeric>
#include <memory>
#include <string>
#include <vector>
#include <set>
#include <stdexcept>

#include <stdlib.h>
#include <assert.h>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_script.h"

namespace cfd {
namespace core {

enum Availability {
  NO,
  YES,
  MAYBE,
};

enum ChallengeType {
    SHA256,
    RIPEMD160,
    HASH256,
    HASH160,
    OLDER,
    AFTER,
    PK
};

/** This type encapsulates the miniscript type system properties.
 *
 * Every miniscript expression is one of 4 basic types, and additionally has
 * a number of boolean type properties.
 *
 * The basic types are:
 * - "B" Base:
 *   - Takes its inputs from the top of the stack.
 *   - When satisfied, pushes a nonzero value of up to 4 bytes onto the stack.
 *   - When dissatisfied, pushes a 0 onto the stack.
 *   - This is used for most expressions, and required for the top level one.
 *   - For example: older(n) = <n> OP_CHECKSEQUENCEVERIFY.
 * - "V" Verify:
 *   - Takes its inputs from the top of the stack.
 *   - When satisfactied, pushes nothing.
 *   - Cannot be dissatisfied.
 *   - This is obtained by adding an OP_VERIFY to a B, modifying the last opcode
 *     of a B to its -VERIFY version (only for OP_CHECKSIG, OP_CHECKSIGVERIFY
 *     and OP_EQUAL), or using IFs where both branches are also Vs.
 *   - For example vc:pk(key) = <key> OP_CHECKSIGVERIFY
 * - "K" Key:
 *   - Takes its inputs from the top of the stack.
 *   - Becomes a B when followed by OP_CHECKSIG.
 *   - Always pushes a public key onto the stack, for which a signature is to be
 *     provided to satisfy the expression.
 *   - For example pk_h(key) = OP_DUP OP_HASH160 <Hash160(key)> OP_EQUALVERIFY
 * - "W" Wrapped:
 *   - Takes its input from one below the top of the stack.
 *   - When satisfied, pushes a nonzero value (like B) on top of the stack, or one below.
 *   - When dissatisfied, pushes 0 op top of the stack or one below.
 *   - Is always "OP_SWAP [B]" or "OP_TOALTSTACK [B] OP_FROMALTSTACK".
 *   - For example sc:pk(key) = OP_SWAP <key> OP_CHECKSIG
 *
 * There a type properties that help reasoning about correctness:
 * - "z" Zero-arg:
 *   - Is known to always consume exactly 0 stack elements.
 *   - For example after(n) = <n> OP_CHECKLOCKTIMEVERIFY
 * - "o" One-arg:
 *   - Is known to always consume exactly 1 stack element.
 *   - Conflicts with property 'z'
 *   - For example sha256(hash) = OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL
 * - "n" Nonzero:
 *   - For every way this expression can be satisfied, a satisfaction exists that never needs
 *     a zero top stack element.
 *   - Conflicts with property 'z' and with type 'W'.
 * - "d" Dissatisfiable:
 *   - There is an easy way to construct a dissatisfaction for this expression.
 *   - Conflicts with type 'V'.
 * - "u" Unit:
 *   - In case of satisfaction, an exact 1 is put on the stack (rather than just nonzero).
 *   - Conflicts with type 'V'.
 *
 * Additional type properties help reasoning about nonmalleability:
 * - "e" Expression:
 *   - This implies property 'd', but the dissatisfaction is nonmalleable.
 *   - This generally requires 'e' for all subexpressions which are invoked for that
 *     dissatifsaction, and property 'f' for the unexecuted subexpressions in that case.
 *   - Conflicts with type 'V'.
 * - "f" Forced:
 *   - Dissatisfactions (if any) for this expression always involve at least one signature.
 *   - Is always true for type 'V'.
 * - "s" Safe:
 *   - Satisfactions for this expression always involve at least one signature.
 * - "m" Nonmalleable:
 *   - For every way this expression can be satisfied (which may be none),
 *     a nonmalleable satisfaction exists.
 *   - This generally requires 'm' for all subexpressions, and 'e' for all subexpressions
 *     which are dissatisfied when satisfying the parent.
 *
 * One final type property is an implementation detail:
 * - "x" Expensive verify:
 *   - Expressions with this property have a script whose last opcode is not EQUAL, CHECKSIG, or CHECKMULTISIG.
 *   - Not having this property means that it can be converted to a V at no cost (by switching to the
 *     -VERIFY version of the last opcode).
 *
 * For each of these properties the subset rule holds: an expression with properties X, Y, and Z, is also
 * valid in places where an X, a Y, a Z, an XY, ... is expected.
*/
class Type {
  //! Internal bitmap of properties (see ""_mst operator for details).
  uint16_t m_flags;

 public:
  //! Internal constructed used by the ""_mst operator.
  explicit Type(uint16_t flags) : m_flags(flags) {}

  //! The only way to publicly construct a Type is using this literal operator.
  // friend Type operator"" _mst(const char* c, size_t l);

  //! Compute the type with the union of properties.
  Type operator|(Type x) const { return Type(m_flags | x.m_flags); }

  //! Compute the type with the intersection of properties.
  Type operator&(Type x) const { return Type(m_flags & x.m_flags); }

  //! Check whether the left hand's properties are superset of the right's (= left is a subtype of right).
  bool operator<<(Type x) const { return (x.m_flags & ~m_flags) == 0; }

  //! Comparison operator to enable use in sets/maps (total ordering incompatible with <<).
  bool operator<(Type x) const { return m_flags < x.m_flags; }
  bool operator>(Type x) const { return m_flags > x.m_flags; }

  //! Equality operator.
  bool operator==(Type x) const { return m_flags == x.m_flags; }

  //! The empty type if x is false, itself otherwise.
  Type If(bool x) const { return Type(x ? m_flags : 0); }
};

// Type operator"" _mst(const char* c, size_t l);
Type ConvStr(const char* c);

std::vector<std::vector<uint8_t>> CreateVectorList(std::vector<uint8_t> arr);

bool IsSpace(char c);
char HexDigit(char c);

using Challenge = std::pair<ChallengeType, uint32_t>;

/** A class encapulating conversion routing for CPubKey. */
class MiniScriptConverter {
 public:
  //! Public keys in text form are their usual hex notation (no xpubs, ...).
  bool ToString(const Pubkey& key, std::string& ret) const;
  bool ToString(const ByteData& key, std::string& ret) const;

  //! Convert a public key to bytes.
  std::vector<uint8_t> ToPKBytes(const Pubkey& key) const;
  ByteData ToPKBytes(const ByteData& key) const;

  //! Convert a public key to its Hash160 bytes (precomputed).
  std::vector<uint8_t> ToPKHBytes(const Pubkey& key) const;
  ByteData ToPKHBytes(const ByteData& key) const;

  //! Parse a public key from a range of hex characters.
  bool FromString(std::string str, ByteData& key) const;

  bool FromPKBytes(const std::vector<uint8_t>& byte_array, ByteData& key) const;

  bool FromPKHBytes(const std::vector<uint8_t>& byte_array, ByteData& key) const;

#if 0
  //! Which keys/timelocks/hash preimages are available.
  std::set<Challenge> supported;

  //! Implement simplified CLTV logic: stack value must exactly match an entry in `supported`.
  bool CheckAfter(uint32_t value) const {
      return supported.count(Challenge(ChallengeType::AFTER, value));
  }

  //! Implement simplified CSV logic: stack value must exactly match an entry in `supported`.
  bool CheckOlder(uint32_t value) const {
      return supported.count(Challenge(ChallengeType::OLDER, value));
  }

  uint32_t static inline ReadLE32(const uint8_t* ptr)
  {
      uint32_t x;
      memcpy((char*)&x, ptr, 4);
      return x;
  }

  uint32_t ChallengeNumber(const Pubkey& pubkey) { return ReadLE32(pubkey.GetData().GetBytes().data() + 29); }
  uint32_t ChallengeNumber(const std::vector<uint8_t>& hash) { return ReadLE32(hash.data()); }

  //! Produce a signature for the given key.
  Availability Sign(const Pubkey& key, std::vector<uint8_t>& sig) const {
      if (supported.count(Challenge(ChallengeType::PK, ChallengeNumber(key)))) {
          auto it = g_testdata->signatures.find(key);
          if (it == g_testdata->signatures.end()) return Availability::NO;
          sig = it->second;
          return Availability::YES;
      }
      return Availability::NO;
  }

  //! Helper function for the various hash based satisfactions.
  Availability SatHash(const std::vector<uint8_t>& hash, std::vector<uint8_t>& preimage, ChallengeType chtype) const {
      if (!supported.count(Challenge(chtype, ChallengeNumber(hash)))) return Availability::NO;
      const auto& m =
          chtype == ChallengeType::SHA256 ? g_testdata->sha256_preimages :
          chtype == ChallengeType::HASH256 ? g_testdata->hash256_preimages :
          chtype == ChallengeType::RIPEMD160 ? g_testdata->ripemd160_preimages :
          g_testdata->hash160_preimages;
      auto it = m.find(hash);
      if (it == m.end()) return Availability::NO;
      preimage = it->second;
      return Availability::YES;
  }

  // Functions that produce the preimage for hashes of various types.
  Availability SatSHA256(const std::vector<uint8_t>& hash, std::vector<uint8_t>& preimage) const { return SatHash(hash, preimage, ChallengeType::SHA256); }
  Availability SatRIPEMD160(const std::vector<uint8_t>& hash, std::vector<uint8_t>& preimage) const { return SatHash(hash, preimage, ChallengeType::RIPEMD160); }
  Availability SatHASH256(const std::vector<uint8_t>& hash, std::vector<uint8_t>& preimage) const { return SatHash(hash, preimage, ChallengeType::HASH256); }
  Availability SatHASH160(const std::vector<uint8_t>& hash, std::vector<uint8_t>& preimage) const { return SatHash(hash, preimage, ChallengeType::HASH160); }
#endif
};

//! The different node types in miniscript.
enum class NodeType {
    JUST_0,    //!< OP_0
    JUST_1,    //!< OP_1
    PK,        //!< [key]
    PK_H,      //!< OP_DUP OP_HASH160 [keyhash] OP_EQUALVERIFY
    OLDER,     //!< [n] OP_CHECKSEQUENCEVERIFY
    AFTER,     //!< [n] OP_CHECKLOCKTIMEVERIFY
    SHA256,    //!< OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 [hash] OP_EQUAL
    HASH256,   //!< OP_SIZE 32 OP_EQUALVERIFY OP_HASH256 [hash] OP_EQUAL
    RIPEMD160, //!< OP_SIZE 32 OP_EQUALVERIFY OP_RIPEMD160 [hash] OP_EQUAL
    HASH160,   //!< OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 [hash] OP_EQUAL
    WRAP_A,    //!< OP_TOALTSTACK [X] OP_FROMALTSTACK
    WRAP_S,    //!< OP_SWAP [X]
    WRAP_C,    //!< [X] OP_CHECKSIG
    WRAP_D,    //!< OP_DUP OP_IF [X] OP_ENDIF
    WRAP_V,    //!< [X] OP_VERIFY (or -VERIFY version of last opcode in X)
    WRAP_J,    //!< OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
    WRAP_N,    //!< [X] OP_0NOTEQUAL
    AND_V,     //!< [X] [Y]
    AND_B,     //!< [X] [Y] OP_BOOLAND
    OR_B,      //!< [X] [Y] OP_BOOLOR
    OR_C,      //!< [X] OP_NOTIF [Y] OP_ENDIF
    OR_D,      //!< [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
    OR_I,      //!< OP_IF [X] OP_ELSE [Y] OP_ENDIF
    ANDOR,     //!< [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
    THRESH,    //!< [X1] ([Xn] OP_ADD)* [k] OP_EQUAL
    THRESH_M,  //!< [k] [key_n]* [n] OP_CHECKMULTISIG
    // AND_N(X,Y) is represented as ANDOR(X,Y,0)
    // WRAP_T(X) is represented as AND_V(X,1)
    // WRAP_L(X) is represented as OR_I(0,X)
    // WRAP_U(X) is represented as OR_I(X,0)
};

//! Helper function for Node::CalcType.
Type ComputeType(NodeType nodetype, Type x, Type y, Type z, const std::vector<Type>& sub_types, uint32_t k, size_t data_size, size_t n_subs, size_t n_keys);

//! Helper function for Node::CalcScriptLen.
size_t ComputeScriptLen(NodeType nodetype, Type sub0typ, size_t subsize, uint32_t k, size_t n_subs, size_t n_keys);

//! A helper sanitizer/checker for the output of CalcType.
Type SanitizeType(Type x);

//! An object representing a sequence of witness stack elements.
struct InputStack {
    /** Whether this stack is valid for its intended purpose (satisfaction or dissatisfaction of a Node).
     *  The MAYBE value is used for size estimation, when keys/preimages may actually be unavailable,
     *  but may be available at signing time. This makes the InputStack structure and signing logic,
     *  filled with dummy signatures/preimages usable for witness size estimation.
     */
    Availability available = Availability::YES;
    //! Whether this stack contains a digital signature.
    bool has_sig = false;
    //! Whether this stack is malleable (can be turned into an equally valid other stack by a third party).
    bool malleable = false;
    //! Whether this stack is non-canonical (using a construction known to be unnecessary for satisfaction).
    bool non_canon = false;
    //! Serialized witness size.
    size_t size = 0;
    //! Data elements.
    std::vector<std::vector<uint8_t>> stack;
    //! Construct an empty stack (valid).
    InputStack() {}
    //! Construct a valid single-element stack (with an element up to 75 bytes).
    InputStack(std::vector<uint8_t> in)
        : size(in.size() + 1), stack(CreateVectorList(in)) {}
    //! Change availability
    InputStack& Available(Availability avail);
    //! Mark this input stack as having a signature.
    InputStack& WithSig();
    //! Mark this input stack as non-canonical (known to not be necessary in non-malleable satisfactions).
    InputStack& NonCanon();
    //! Mark this input stack as malleable.
    InputStack& Malleable(bool x = true);
    //! Concatenate two input stacks.
    friend InputStack operator+(InputStack a, InputStack b);
    //! Choose between two potential input stacks.
    friend InputStack Choose(InputStack a, InputStack b, bool nonmalleable);
};

//! A pair of a satisfaction and a dissatisfaction InputStack.
struct InputResult {
    InputStack nsat, sat;
    InputResult(InputStack in_nsat, InputStack in_sat) : nsat(in_nsat), sat(in_sat) {}
};

//! Class whose objects represent the maximum of a list of integers.
template<typename I>
struct MaxInt {
  bool valid;
  I value;

  MaxInt() : valid(false), value(0) {}
  MaxInt(I val) : valid(true), value(val) {}

  friend MaxInt<I> operator+(const MaxInt<I>& a, const MaxInt<I>& b) {
    if (!a.valid && !b.valid)
      throw cfd::core::CfdException("MaxInt operator+ error. a=" + std::to_string(a.value) + ", b=" + std::to_string(b.value));
    if (!a.valid) return b.value;
    if (!b.valid) return a.value;
    return a.value + b.value;
  }

  friend MaxInt<I> Choose(const MaxInt<I>& a, const MaxInt<I>& b) {
      if (!a.valid) return b;
      if (!b.valid) return a;
      return std::max(a.value, b.value);
  }

  MaxInt<I>& operator=(const MaxInt<I>& data) {
    valid = data.valid;
    value = data.value;
    return *this;
  }
};

class Ops {
 public:
  //! Non-push opcodes.
  uint32_t stat;
  //! Number of keys in possibly executed OP_CHECKMULTISIG(VERIFY)s to satisfy.
  MaxInt<uint32_t> sat;
  //! Number of keys in possibly executed OP_CHECKMULTISIG(VERIFY)s to dissatisfy.
  MaxInt<uint32_t> dsat;

  Ops(uint32_t in_stat, MaxInt<uint32_t> in_sat, MaxInt<uint32_t> in_dsat)
      : stat(in_stat), sat(in_sat), dsat(in_dsat) {};

  Ops& operator=(const Ops& data) {
    stat = data.stat;
    sat.valid = data.sat.valid;
    sat.value = data.sat.value;
    dsat.valid = data.dsat.valid;
    dsat.value = data.dsat.value;
    return *this;
  }
};

class StackSize {
 public:
  //! Maximum stack size to satisfy;
  MaxInt<uint32_t> sat;
  //! Maximum stack size to dissatisfy;
  MaxInt<uint32_t> dsat;

  StackSize(MaxInt<uint32_t> in_sat, MaxInt<uint32_t> in_dsat)
      : sat(in_sat), dsat(in_dsat) {};

  StackSize& operator=(const StackSize& data) {
    sat.valid = data.sat.valid;
    sat.value = data.sat.value;
    dsat.valid = data.dsat.valid;
    dsat.value = data.dsat.value;
    return *this;
  }
};

//! A node in a miniscript expression.
class Node {
 private:
    MiniScriptConverter converter;
    //! What node type this node is.
    NodeType nodetype;
    //! The k parameter (time for OLDER/AFTER, threshold for THRESH(_M))
    uint32_t k = 0;
    //! The keys used by this expression (only for PK/PK_H/THRESH_M)
    std::vector<ByteData> keys;
    //! The data bytes in this expression (only for HASH160/HASH256/SHA256/RIPEMD10).
    ByteData data;
    //! Subexpressions (for WRAP_*/AND_*/OR_*/ANDOR/THRESH)
    std::vector<Node> subs;


    // Maximum number of non-push operations per script
    static const int MAX_OPS_PER_SCRIPT = 201;

    static const unsigned int MAX_STANDARD_P2WSH_STACK_ITEMS = 100;

    //! Cached ops counts.
    Ops ops;
    //! Cached stack size bounds.
    StackSize ss;
    //! Cached expression type (computed by CalcType and fed through SanitizeType).
    Type typ;
    //! Cached script length (computed by CalcScriptLen).
    size_t scriptlen;

    //! Compute the length of the script for this miniscript (including children).
    size_t CalcScriptLen() const;

    //! Compute the type for this miniscript.
    Type CalcType() const;

    //! Internal code for ToScript.
    ScriptBuilder MakeScript(const MiniScriptConverter& ctx, bool verify = false) const;

    //! Internal code for ToString.
    std::string MakeString(const MiniScriptConverter& ctx, bool& success, bool wrapped = false) const;

    Ops CalcOps() const;

    StackSize CalcStackSize() const;

    InputResult ProduceInput(const MiniScriptConverter& ctx, bool nonmal) const;

    InputResult ProduceInputHelper(const MiniScriptConverter& ctx, bool nonmal) const;

public:
    //! Return the size of the script for this expression (faster than ToString().size()).
    size_t ScriptSize() const { return scriptlen; }

    //! Return the maximum number of ops needed to satisfy this script non-malleably.
    uint32_t GetOps() const { return ops.stat + ops.sat.value; }

    //! Check the ops limit of this script against the consensus limit.
    bool CheckOpsLimit() const { return GetOps() <= MAX_OPS_PER_SCRIPT; }

    //! Return the maximum number of stack elements needed to satisfy this script non-malleably.
    uint32_t GetStackSize() const { return ss.sat.value; }

    //! Check the maximum stack size for this script against the policy limit.
    bool CheckStackSize() const { return GetStackSize() <= MAX_STANDARD_P2WSH_STACK_ITEMS; }

    //! Return the expression type.
    Type GetType() const { return typ; }

    //! Check whether this node is valid at all.
    bool IsValid() const { return !(GetType() == Type(0)); }

    //! Check whether this node is valid as a script on its own.
    bool IsValidTopLevel() const { return GetType() << ConvStr("B"); }

    //! Check whether this script can always be satisfied in a non-malleable way.
    bool IsNonMalleable() const { return GetType() << ConvStr("m"); }

    //! Check whether this script always needs a signature.
    bool NeedsSignature() const { return GetType() << ConvStr("s"); }

    //! Do all sanity checks.
    bool IsSafeTopLevel() const { return GetType() << ConvStr("Bms") && CheckOpsLimit() && CheckStackSize(); }

    //! Construct the script for this miniscript (including subexpressions).
    Script ToScript(const MiniScriptConverter& ctx) const { return MakeScript(ctx).Build(); }

    //! Convert this miniscript to its textual descriptor notation.
    bool ToString(const MiniScriptConverter& ctx, std::string& out) const;

    Availability Satisfy(const MiniScriptConverter& ctx, std::vector<std::vector<uint8_t>>& stack, bool nonmalleable = true) const;

    //! Equality testing.
    bool operator==(const Node& arg) const;

    Node& operator=(const Node& node_data);

    // Constructors with various argument combinations.
    Node(NodeType nt, std::vector<Node> sub, std::vector<uint8_t> arg, uint32_t val = 0)
      : nodetype(nt), k(val), data(ByteData(arg)), subs(sub), ops(CalcOps()), ss(CalcStackSize()), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, ByteData arg, uint32_t val = 0)
      : nodetype(nt), k(val), data(arg), ops(CalcOps()), ss(CalcStackSize()), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, std::vector<Node> sub, std::vector<ByteData> key, uint32_t val = 0)
      : nodetype(nt), k(val), keys(key), subs(sub), ops(CalcOps()), ss(CalcStackSize()), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, std::vector<ByteData> key, uint32_t val = 0)
      : nodetype(nt), k(val), keys(key), ops(CalcOps()), ss(CalcStackSize()), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, std::vector<Node> sub)
      : nodetype(nt), k(0), subs(sub), ops(CalcOps()), ss(CalcStackSize()), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, uint32_t val = 0)
      : nodetype(nt), k(val), ops(CalcOps()), ss(CalcStackSize()), typ(CalcType()), scriptlen(CalcScriptLen()) {}

};

bool Const(const std::string& str, const std::string& sp, std::string* out);

std::string Expr(const std::string& sp, std::string* out);

// Parse(...) is recursive. Recursion depth is limited to MAX_PARSE_RECURSION to avoid
// running out of stack space at run-time. It is impossible to create a valid Miniscript
// with a nesting depth higher than 402 (any such script will trivially exceed the ops
// limit of 201). Those 402 consist of 201 v: wrappers and 201 other nodes. The Parse
// functions don't use recursion for wrappers, so the recursion limit can be 201.
static constexpr int MAX_PARSE_RECURSION = 201;

//! Parse a miniscript from its textual descriptor form.
Node Parse(std::string in, const MiniScriptConverter& ctx, int recursion_depth, std::string* out);

/** Decode a script into opcode/push pairs.
 *
 * Construct a vector with one element per opcode in the script, in reverse order.
 * Each element is a pair consisting of the opcode, as well as the data pushed by
 * the opcode (including OP_n), if any. OP_CHECKSIGVERIFY, OP_CHECKMULTISIGVERIFY,
 * and OP_EQUALVERIFY are decomposed into OP_CHECKSIG, OP_CHECKMULTISIG, OP_EQUAL
 * respectively, plus OP_VERIFY.
 */
bool DecomposeScript(const Script& script, std::vector<std::pair<ScriptOperator, std::vector<uint8_t>>>& out);

/** Determine whether the passed pair (created by DecomposeScript) is pushing a number. */
bool ParseScriptNumber(const std::pair<ScriptOperator, std::vector<uint8_t>>& in, int64_t& k);

using ScriptObject = std::vector<std::pair<ScriptOperator, std::vector<uint8_t>>>::iterator;

using ScriptObjectIte = std::vector<std::pair<ScriptOperator, std::vector<uint8_t>>>::iterator;

//! Decode a list of script elements into a miniscript (except and_v, s:, and a:).
Node DecodeSingle(ScriptObjectIte& in, ScriptObject last, const MiniScriptConverter& ctx);

//! Decode a list of script elements into a miniscript (except a: and s:)
Node DecodeMulti(ScriptObjectIte& in, ScriptObject last, const MiniScriptConverter& ctx);

//! Decode a list of script elements into a miniscript (only a: and s:)
Node DecodeWrapped(ScriptObjectIte& in, ScriptObject last, const MiniScriptConverter& ctx);

/**
 * @brief miniscript文字列からScript Nodeを生成します。
 */
Node FromString(const std::string& str, const MiniScriptConverter& ctx);

/**
 * @brief ScriptからScript Nodeを生成します。
 */
Node FromScript(const Script& script, const MiniScriptConverter& ctx);

} // namespace core
} // namespace cfd

#endif // BITCOIN_SCRIPT_MINISCRIPT_H
