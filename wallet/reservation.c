/* Dealing with reserving UTXOs */
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/mem/mem.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/key_derive.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <wallet/wallet.h>
#include <wallet/walletrpc.h>

static bool was_reserved(enum output_status oldstatus,
			 u32 reserved_til,
			 u32 current_height)
{
	if (oldstatus != OUTPUT_STATE_RESERVED)
		return false;

	return reserved_til > current_height;
}

static void json_add_reservestatus(struct json_stream *response,
				   const struct utxo *utxo,
				   enum output_status oldstatus,
				   u32 old_res,
				   u32 current_height)
{
	json_object_start(response, NULL);
	json_add_txid(response, "txid", &utxo->txid);
	json_add_u32(response, "vout", utxo->outnum);
	json_add_bool(response, "was_reserved",
		      was_reserved(oldstatus, old_res, current_height));
	json_add_bool(response, "reserved",
		      utxo_is_reserved(utxo, current_height));
	if (utxo_is_reserved(utxo, current_height))
		json_add_u32(response, "reserved_to_block",
			     utxo->reserved_til);
	json_object_end(response);
}

/* Reserve these UTXOs and print to JSON */
static void reserve_and_report(struct json_stream *response,
			       struct wallet *wallet,
			       u32 current_height,
			       struct utxo **utxos)
{
	json_array_start(response, "reservations");
	for (size_t i = 0; i < tal_count(utxos); i++) {
		enum output_status oldstatus;
		u32 old_res;

		oldstatus = utxos[i]->status;
		old_res = utxos[i]->reserved_til;

		if (!wallet_reserve_utxo(wallet,
					 utxos[i],
					 current_height)) {
			fatal("Unable to reserve %s:%u!",
			      type_to_string(tmpctx,
					     struct bitcoin_txid,
					     &utxos[i]->txid),
			      utxos[i]->outnum);
		}
		json_add_reservestatus(response, utxos[i], oldstatus, old_res,
				       current_height);
	}
	json_array_end(response);
}

static struct command_result *json_reserveinputs(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct json_stream *response;
	struct wally_psbt *psbt;
	struct utxo **utxos = tal_arr(cmd, struct utxo *, 0);
	bool *exclusive;
	u32 current_height;

	if (!param(cmd, buffer, params,
		   p_req("psbt", param_psbt, &psbt),
		   p_opt_def("exclusive", param_bool, &exclusive, true),
		   NULL))
		return command_param_failed();

	current_height = get_block_height(cmd->ld->topology);
	for (size_t i = 0; i < psbt->tx->num_inputs; i++) {
		struct bitcoin_txid txid;
		struct utxo *utxo;

		wally_tx_input_get_txid(&psbt->tx->inputs[i], &txid);
		utxo = wallet_utxo_get(cmd, cmd->ld->wallet,
				       &txid, psbt->tx->inputs[i].index);
		if (!utxo)
			continue;
		if (*exclusive && utxo_is_reserved(utxo, current_height)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s:%u already reserved",
					    type_to_string(tmpctx,
							   struct bitcoin_txid,
							   &utxo->txid),
					    utxo->outnum);
		}
		if (utxo->status == OUTPUT_STATE_SPENT)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s:%u already spent",
					    type_to_string(tmpctx,
							   struct bitcoin_txid,
							   &utxo->txid),
					    utxo->outnum);
		tal_arr_expand(&utxos, utxo);
	}

	response = json_stream_success(cmd);
	reserve_and_report(response, cmd->ld->wallet, current_height, utxos);
	return command_success(cmd, response);
}

static const struct json_command reserveinputs_command = {
	"reserveinputs",
	"bitcoin",
	json_reserveinputs,
	"Reserve utxos (or increase their reservation)",
	false
};
AUTODATA(json_command, &reserveinputs_command);

static struct command_result *json_unreserveinputs(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *obj UNNEEDED,
						   const jsmntok_t *params)
{
	struct json_stream *response;
	struct wally_psbt *psbt;

	if (!param(cmd, buffer, params,
		   p_req("psbt", param_psbt, &psbt),
		   NULL))
		return command_param_failed();

	/* We should also add the utxo info for these inputs!
	 * (absolutely required for using this psbt in a dual-funded
	 * round) */
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct bitcoin_tx *utxo_tx;
		struct bitcoin_txid txid;

		wally_tx_input_get_txid(&psbt->tx->inputs[i], &txid);
		utxo_tx = wallet_transaction_get(psbt, cmd->ld->wallet,
						 &txid);
		if (utxo_tx)
			wally_psbt_input_set_utxo(&psbt->inputs[i],
						  utxo_tx->wtx);
		else
			log_broken(cmd->ld->log,
				   "No transaction found for UTXO %s",
				   type_to_string(tmpctx, struct bitcoin_txid,
						  &txid));
	}

	response = json_stream_success(cmd);
	json_array_start(response, "reservations");
	for (size_t i = 0; i < psbt->tx->num_inputs; i++) {
		struct bitcoin_txid txid;
		struct utxo *utxo;
		enum output_status oldstatus;
		u32 old_res;

		wally_tx_input_get_txid(&psbt->tx->inputs[i], &txid);
		utxo = wallet_utxo_get(cmd, cmd->ld->wallet,
				       &txid, psbt->tx->inputs[i].index);
		if (!utxo || utxo->status != OUTPUT_STATE_RESERVED)
			continue;

		oldstatus = utxo->status;
		old_res = utxo->reserved_til;

		wallet_unreserve_utxo(cmd->ld->wallet,
				      utxo,
				      get_block_height(cmd->ld->topology));

		json_add_reservestatus(response, utxo, oldstatus, old_res,
				       get_block_height(cmd->ld->topology));
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command unreserveinputs_command = {
	"unreserveinputs",
	"bitcoin",
	json_unreserveinputs,
	"Unreserve utxos (or at least, reduce their reservation)",
	false
};
AUTODATA(json_command, &unreserveinputs_command);

/**
 * inputs_sufficient - are we there yet?
 * @input: total input amount
 * @amount: required output amount
 * @feerate_per_kw: feerate we have to pay
 * @weight: weight of transaction so far.
 * @diff: (output) set to amount over or under requirements.
 *
 * Returns true if inputs >= fees + amount, otherwise false.  diff is
 * the amount over (if returns true) or under (if returns false)
 */
static bool inputs_sufficient(struct amount_sat input,
			      struct amount_sat amount,
			      u32 feerate_per_kw,
			      size_t weight,
			      struct amount_sat *diff)
{
	struct amount_sat fee;

	fee = amount_tx_fee(feerate_per_kw, weight);

	/* If we can't add fees, amount is huge (e.g. "all") */
	if (!amount_sat_add(&amount, amount, fee))
		return false;

	/* One of these must work! */
	if (amount_sat_sub(diff, input, amount))
		return true;
	if (!amount_sat_sub(diff, amount, input))
		abort();
	return false;
}

static struct wally_psbt *psbt_using_utxos(const tal_t *ctx,
					   struct utxo **utxos,
					   const struct ext_key *bip32_base,
					   u32 nlocktime,
					   u32 nsequence)
{
	struct pubkey key;
	u8 *scriptSig, *scriptPubkey, *redeemscript;
	struct wally_psbt *psbt;

	psbt = create_psbt(ctx, tal_count(utxos), 0, nlocktime);

	for (size_t i = 0; i < tal_count(utxos); i++) {
		u32 this_nsequence;

		if (utxos[i]->is_p2sh) {
			bip32_pubkey(bip32_base, &key, utxos[i]->keyindex);
			scriptSig = bitcoin_scriptsig_p2sh_p2wpkh(tmpctx, &key);
			redeemscript = bitcoin_redeem_p2sh_p2wpkh(tmpctx, &key);
			scriptPubkey = scriptpubkey_p2sh(tmpctx, redeemscript);

			/* Make sure we've got the right info! */
			if (utxos[i]->scriptPubkey)
				assert(memeq(utxos[i]->scriptPubkey,
					     tal_bytelen(utxos[i]->scriptPubkey),
					     scriptPubkey, tal_bytelen(scriptPubkey)));
		} else {
			scriptSig = NULL;
			redeemscript = NULL;
			scriptPubkey = utxos[i]->scriptPubkey;
		}

		/* BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
		 * #### `to_remote` Output
		 * ...
		 * The output is spent by a transaction with `nSequence` field
		 * set to `1` and witness:
		 */
		if (utxos[i]->close_info
		    && utxos[i]->close_info->option_anchor_outputs)
			this_nsequence = 1;
		else
			this_nsequence = nsequence;

		psbt_append_input(psbt, &utxos[i]->txid, utxos[i]->outnum,
				  this_nsequence, scriptSig,
				  NULL, redeemscript);

		psbt_input_set_wit_utxo(psbt, i, scriptPubkey, utxos[i]->amount);
	}

	return psbt;
}

static struct command_result *finish_psbt(struct command *cmd,
					  struct utxo **utxos,
					  u32 feerate_per_kw,
					  size_t weight,
					  struct amount_sat excess,
					  bool reserve,
					  u32 *locktime)
{
	struct json_stream *response;
	struct wally_psbt *psbt;
	u32 current_height = get_block_height(cmd->ld->topology);

	/* Setting the locktime to the next block to be mined has multiple
	 * benefits:
	 * - anti fee-snipping (even if not yet likely)
	 * - less distinguishable transactions (with this we create
	 *   general-purpose transactions which looks like bitcoind:
	 *   native segwit, nlocktime set to tip, and sequence set to
	 *   0xFFFFFFFD by default. Other wallets are likely to implement
	 *   this too).
	 */
	if (!locktime) {
		locktime = tal(cmd, u32);
		*locktime = current_height;

		/* Eventually fuzz it too. */
		if (*locktime > 100 && pseudorand(10) == 0)
			*locktime -= pseudorand(100);
	}

	psbt = psbt_using_utxos(cmd, utxos, cmd->ld->wallet->bip32_base,
				*locktime, BITCOIN_TX_RBF_SEQUENCE);

	/* Add a fee output if this is elements */
	if (is_elements(chainparams)) {
		struct amount_sat est_fee =
			amount_tx_fee(feerate_per_kw, weight);
		psbt_append_output(psbt, NULL, est_fee);
	}
	response = json_stream_success(cmd);
	json_add_psbt(response, "psbt", psbt);
	json_add_num(response, "feerate_per_kw", feerate_per_kw);
	json_add_num(response, "estimated_final_weight", weight);
	json_add_amount_sat_only(response, "excess_msat", excess);
	if (reserve)
		reserve_and_report(response, cmd->ld->wallet, current_height,
				   utxos);
	return command_success(cmd, response);
}

static inline u32 minconf_to_maxheight(u32 minconf, struct lightningd *ld)
{
	/* No confirmations is special, we need to disable the check in the
	 * selection */
	if (minconf == 0)
		return 0;

	/* Avoid wrapping around and suddenly allowing any confirmed
	 * outputs. Since we can't have a coinbase output, and 0 is taken for
	 * the disable case, we can just clamp to 1. */
	if (minconf >= ld->topology->tip->height)
		return 1;
	return ld->topology->tip->height - minconf + 1;
}

static struct command_result *json_fundpsbt(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *obj UNNEEDED,
					      const jsmntok_t *params)
{
	struct utxo **utxos;
	u32 *feerate_per_kw;
	u32 *minconf, *weight;
	struct amount_sat *amount, input, diff;
	bool all, *reserve;
	u32 *locktime, maxheight;

	if (!param(cmd, buffer, params,
		   p_req("satoshi", param_sat_or_all, &amount),
		   p_req("feerate", param_feerate, &feerate_per_kw),
		   p_req("startweight", param_number, &weight),
		   p_opt_def("minconf", param_number, &minconf, 1),
		   p_opt_def("reserve", param_bool, &reserve, true),
		   p_opt("locktime", param_number, &locktime),
		   NULL))
		return command_param_failed();

	all = amount_sat_eq(*amount, AMOUNT_SAT(-1ULL));
	maxheight = minconf_to_maxheight(*minconf, cmd->ld);

	/* We keep adding until we meet their output requirements. */
	utxos = tal_arr(cmd, struct utxo *, 0);

	input = AMOUNT_SAT(0);
	while (!inputs_sufficient(input, *amount, *feerate_per_kw, *weight,
				  &diff)) {
		struct utxo *utxo;

		utxo = wallet_find_utxo(utxos, cmd->ld->wallet,
					cmd->ld->topology->tip->height,
					&diff,
					*feerate_per_kw,
					maxheight,
					cast_const2(const struct utxo **, utxos));
		if (utxo) {
			tal_arr_expand(&utxos, utxo);

			/* It supplies more input. */
			if (!amount_sat_add(&input, input, utxo->amount))
				return command_fail(cmd, LIGHTNINGD,
						    "impossible UTXO value");

			/* But also adds weight */
			*weight += utxo_spend_weight(utxo);
			continue;
		}

		/* If they said "all", we expect to run out of utxos. */
		if (all && tal_count(utxos))
			break;

		/* Since it's possible the lack of utxos is because we haven't
		 * finished syncing yet, report a sync timing error first */
		if (!topology_synced(cmd->ld->topology))
			return command_fail(cmd,
					    FUNDING_STILL_SYNCING_BITCOIN,
					    "Cannot afford: still syncing with bitcoin network...");

		return command_fail(cmd, FUND_CANNOT_AFFORD,
				    "Could not afford %s using all %zu available UTXOs: %s short",
				    all ? "all"
				    : type_to_string(tmpctx,
						     struct amount_sat,
						     amount),
				    tal_count(utxos),
				    all ? "all"
				    : type_to_string(tmpctx,
						     struct amount_sat,
						     &diff));
	}

	if (all) {
		/* Anything above 0 is "excess" */
		if (!inputs_sufficient(input, AMOUNT_SAT(0),
				       *feerate_per_kw, *weight,
				       &diff)) {
			if (!topology_synced(cmd->ld->topology))
				return command_fail(cmd,
						    FUNDING_STILL_SYNCING_BITCOIN,
						    "Cannot afford: still syncing with bitcoin network...");
			return command_fail(cmd, FUND_CANNOT_AFFORD,
					    "All %zu inputs could not afford"
					    " fees",
					    tal_count(utxos));
		}
	}

	return finish_psbt(cmd, utxos, *feerate_per_kw, *weight, diff, *reserve,
			   locktime);
}

static const struct json_command fundpsbt_command = {
	"fundpsbt",
	"bitcoin",
	json_fundpsbt,
	"Create PSBT using enough utxos to allow an output of {satoshi} at {feerate}",
	false
};
AUTODATA(json_command, &fundpsbt_command);

static struct command_result *param_txout(struct command *cmd,
					  const char *name,
					  const char *buffer,
					  const jsmntok_t *tok,
					  struct utxo ***utxos)
{
	size_t i;
	const jsmntok_t *curr;

	*utxos = tal_arr(cmd, struct utxo *, tok->size);

	json_for_each_arr(i, curr, tok) {
		struct utxo *utxo;
		jsmntok_t txid_tok, outnum_tok;
		struct bitcoin_txid txid;
		u32 outnum;

		if (!split_tok(buffer, curr, ':', &txid_tok, &outnum_tok))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not decode the outpoint from \"%s\""
					    " The utxos should be specified as"
					    " 'txid:output_index'.",
					    json_strdup(tmpctx, buffer, curr));

		if (!json_to_txid(buffer, &txid_tok, &txid)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not get a txid out of \"%s\"",
					    json_strdup(tmpctx, buffer, &txid_tok));
		}
		if (!json_to_number(buffer, &outnum_tok, &outnum)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not get a vout out of \"%s\"",
					    json_strdup(tmpctx, buffer, &outnum_tok));
		}

		utxo = wallet_utxo_get(*utxos, cmd->ld->wallet, &txid, outnum);
		if (!utxo) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Unknown UTXO %s:%u",
					    type_to_string(tmpctx,
							   struct bitcoin_txid,
							   &txid),
					    outnum);
		}
		if (utxo->status == OUTPUT_STATE_SPENT) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Already spent UTXO %s:%u",
					    type_to_string(tmpctx,
							   struct bitcoin_txid,
							   &txid),
					    outnum);
		}

		(*utxos)[i] = utxo;
	}

	if (i == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Please specify an array of 'txid:output_index',"
				    " not \"%.*s\"",
				    tok->end - tok->start,
				    buffer + tok->start);
	return NULL;
}

static struct command_result *json_utxopsbt(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct utxo **utxos;
	u32 *feerate_per_kw, *weight;
	bool all, *reserve, *reserved_ok;
	struct amount_sat *amount, input, excess;
	u32 current_height, *locktime;

	if (!param(cmd, buffer, params,
		   p_req("satoshi", param_sat_or_all, &amount),
		   p_req("feerate", param_feerate, &feerate_per_kw),
		   p_req("startweight", param_number, &weight),
		   p_req("utxos", param_txout, &utxos),
		   p_opt_def("reserve", param_bool, &reserve, true),
		   p_opt_def("reservedok", param_bool, &reserved_ok, false),
		   p_opt("locktime", param_number, &locktime),
		   NULL))
		return command_param_failed();

	all = amount_sat_eq(*amount, AMOUNT_SAT(-1ULL));

	input = AMOUNT_SAT(0);
	current_height = get_block_height(cmd->ld->topology);
	for (size_t i = 0; i < tal_count(utxos); i++) {
		const struct utxo *utxo = utxos[i];

		if (!*reserved_ok && utxo_is_reserved(utxo, current_height))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "UTXO %s:%u already reserved",
					    type_to_string(tmpctx,
							   struct bitcoin_txid,
							   &utxo->txid),
					    utxo->outnum);

		/* It supplies more input. */
		if (!amount_sat_add(&input, input, utxo->amount))
			return command_fail(cmd, LIGHTNINGD,
					    "impossible UTXO value");

		/* But also adds weight */
		*weight += utxo_spend_weight(utxo);
	}

	/* For all, anything above 0 is "excess" */
	if (!inputs_sufficient(input, all ? AMOUNT_SAT(0) : *amount,
			       *feerate_per_kw, *weight, &excess)) {
		return command_fail(cmd, FUND_CANNOT_AFFORD,
				    "Could not afford %s using UTXOs totalling %s with weight %u at feerate %u",
				    all ? "anything" :
				    type_to_string(tmpctx,
						   struct amount_sat,
						   amount),
				    type_to_string(tmpctx,
						   struct amount_sat,
						   &input),
				    *weight, *feerate_per_kw);
	}

	return finish_psbt(cmd, utxos, *feerate_per_kw, *weight, excess,
			   *reserve, locktime);
}
static const struct json_command utxopsbt_command = {
	"utxopsbt",
	"bitcoin",
	json_utxopsbt,
	"Create PSBT using these utxos",
	false
};
AUTODATA(json_command, &utxopsbt_command);
