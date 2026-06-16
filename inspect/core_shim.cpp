// inspect/core_shim.cpp
//
// A tiny C shim over Bitcoin Core's *compiled* libbitcoinkernel: it constructs a
// TransactionSignatureChecker from the spending tx + the (single) spent output
// and calls Core's real VerifyScript with the raw flags.  This lets us pass the
// FULL SCRIPT_VERIFY_* flag set (consensus AND policy, incl. TAPROOT) — more than
// the old libbitcoinconsensus C API exposed.
//
// Built for the 1-input synthetic txs the fuzzer/conformance harness uses
// (spent_outputs is just the one prevout, which is all taproot needs there).
//
// Compile: see inspect/build-libkernel.sh.

#include <script/interpreter.h>
#include <script/script.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <span.h>
#include <vector>
#include <cstddef>
#include <cstdint>

// Verify input `input_index` of a tx given ALL spent outputs (needed for taproot,
// whose sighash commits to every prevout).  `spents` is a concatenation of
// serialized CTxOut (value || varint-len || scriptPubKey), one per input.
extern "C" int core_verify_tx(
    const unsigned char* txto, std::size_t txto_len,
    const unsigned char* spents, std::size_t spents_len,
    unsigned int input_index, unsigned int flags)
{
    try {
        DataStream ss{std::span<const unsigned char>{txto, txto_len}};
        CMutableTransaction mtx;
        ss >> TX_WITH_WITNESS(mtx);
        const CTransaction tx{mtx};

        std::vector<CTxOut> spent;
        DataStream ps{std::span<const unsigned char>{spents, spents_len}};
        while (!ps.empty()) { CTxOut o; ps >> o; spent.push_back(o); }
        if (input_index >= tx.vin.size() || input_index >= spent.size()) return -1;

        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>(spent), /*force=*/true);
        const CTxOut& utxo = spent[input_index];
        TransactionSignatureChecker checker(&tx, input_index, utxo.nValue, txdata,
                                            MissingDataBehavior::FAIL);
        ScriptError err;
        bool ok = VerifyScript(tx.vin[input_index].scriptSig, utxo.scriptPubKey,
                               &tx.vin[input_index].scriptWitness, flags, checker, &err);
        return ok ? 1 : 0;
    } catch (...) {
        return -1;
    }
}

extern "C" int core_verify_script(
    const unsigned char* spk, std::size_t spk_len,
    std::int64_t amount,
    const unsigned char* txto, std::size_t txto_len,
    unsigned int n_in, unsigned int flags)
{
    try {
        CScript scriptPubKey(spk, spk + spk_len);

        DataStream ss{std::span<const unsigned char>{txto, txto_len}};
        CMutableTransaction mtx;
        ss >> TX_WITH_WITNESS(mtx);
        const CTransaction tx{mtx};
        if (n_in >= tx.vin.size()) return -1;

        std::vector<CTxOut> spent;
        spent.emplace_back(CAmount(amount), scriptPubKey);   // the one prevout
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>(spent), /*force=*/true);

        TransactionSignatureChecker checker(&tx, n_in, CAmount(amount), txdata,
                                            MissingDataBehavior::FAIL);
        const CScriptWitness& witness = tx.vin[n_in].scriptWitness;
        ScriptError err;
        bool ok = VerifyScript(tx.vin[n_in].scriptSig, scriptPubKey, &witness,
                               flags, checker, &err);
        return ok ? 1 : 0;
    } catch (...) {
        return -1;  // deserialization / construction failure
    }
}
