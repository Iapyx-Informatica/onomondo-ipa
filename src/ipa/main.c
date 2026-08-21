/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/ipad.h>

#define DEFAULT_READER_NUMBER 0
#define DEFAULT_CHANNEL_NUMBER 1
#define DEFAULT_TAC "12345678"
#define DEFAULT_NVSTATE_PATH "./nvstate.bin"
#define DEFAULT_ESIPA_REQ_RETRIES 3

bool running = true;

bool prfle_inst_consent(char *sm_dp_plus_address, char *ac_token)
{
	char user_input;
	printf("PLEASE CONSENT TO PROFILE INSTALLATION:\n");
	printf("smdp+: %s\n", sm_dp_plus_address);
	printf("ac-token: %s\n", ac_token);
	printf("Consent (Y/N)? ");
	user_input = getchar();
	if (user_input == 'Y' || user_input == 'y')
		return true;
	return false;
}

/* Print every subsystem and level name the -l and -d options accept. The names come from libipa rather than from a
 * list kept here, so that adding a subsystem does not silently leave the help text (or the parser) behind. */
static void print_log_names(void)
{
	unsigned int i;

	fprintf(stderr, "subsystems:");
	for (i = 0; i < _NUM_LOG_SUBSYS; i++)
		fprintf(stderr, " %s", ipa_log_subsys_name(i));
	fprintf(stderr, "\nlevels:");
	for (i = 0; i < _NUM_LOG_LEVEL; i++)
		fprintf(stderr, " %s", ipa_log_level_name(i));
	fprintf(stderr, "\n");
}

/*! Parse the argument of -l (a level, applying to every subsystem) or -d (SUBSYS:LEVEL, applying to one).
 *  \param[in] arg option argument.
 *  \param[in] per_subsys true when arg carries a subsystem prefix, i.e. the option was -d.
 *  \returns 0 on success, -EINVAL when a name is not recognised or the syntax is wrong. */
static int parse_log_level_opt(const char *arg, bool per_subsys)
{
	char buf[32];
	char *sep;
	int subsys;
	int level;

	if (!per_subsys) {
		level = ipa_log_level_by_name(arg);
		if (level < 0) {
			fprintf(stderr, "unknown log level \"%s\"\n", arg);
			print_log_names();
			return -EINVAL;
		}
		ipa_log_set_level_all(level);
		return 0;
	}

	/* Split SUBSYS:LEVEL in a scratch copy: optarg points into argv, which is not ours to modify. */
	if (strlen(arg) >= sizeof(buf)) {
		fprintf(stderr, "log level specification \"%s\" is too long\n", arg);
		return -EINVAL;
	}
	strcpy(buf, arg);

	sep = strchr(buf, ':');
	if (!sep) {
		fprintf(stderr, "log level specification \"%s\" is not of the form SUBSYS:LEVEL\n", arg);
		print_log_names();
		return -EINVAL;
	}
	*sep = '\0';

	subsys = ipa_log_subsys_by_name(buf);
	if (subsys < 0) {
		fprintf(stderr, "unknown log subsystem \"%s\"\n", buf);
		print_log_names();
		return -EINVAL;
	}

	level = ipa_log_level_by_name(sep + 1);
	if (level < 0) {
		fprintf(stderr, "unknown log level \"%s\"\n", sep + 1);
		print_log_names();
		return -EINVAL;
	}

	ipa_log_set_level(subsys, level);
	return 0;
}

static void print_help(void)
{
	printf("options:\n");
	printf(" -h .................. print this text.\n");
	printf(" -t TAC .............. set TAC (default: %s)\n", DEFAULT_TAC);
	printf(" -M IMEI ............. set IMEI, %d hex digits (default: not sent, it is optional)\n",
	       IPA_LEN_IMEI * 2);
	printf(" -e eimId ............ set preferred eIM (in case the eUICC has multiple)\n");
	printf(" -r N ................ set reader number (default: %d)\n", DEFAULT_READER_NUMBER);
	printf(" -c N ................ set logical channel number (default: %d)\n", DEFAULT_CHANNEL_NUMBER);
	printf(" -f PATH ............. set initial eIM configuration\n");
	printf(" -m .................. reset eUICC memory\n");
	printf(" -n PATH ............. path to nvstate file (default: %s)\n", DEFAULT_NVSTATE_PATH);
	printf(" -y NUM .............. number of retries for ESipa requests (default: %u)\n",
	       DEFAULT_ESIPA_REQ_RETRIES);
	printf(" -a .................. ask end user for consent\n");
	printf(" -C .................. CA (Certificate Authority) Bundle file\n");
	printf(" -S .................. disable HTTPS\n");
	printf(" -I .................. disable SSL certificate verification (insecure)\n");
	printf(" -L .................. prefix each log line with the source file and line that produced it\n");
	printf(" -l LEVEL ............ set the log level of every subsystem (default: %s)\n",
	       ipa_log_level_name(LDEBUG));
	printf(" -d SUBSYS:LEVEL ..... set the log level of one subsystem, may be given more than once\n");
	printf("                       (applied in the order given, so -l %s -d %s:%s works as it reads)\n",
	       ipa_log_level_name(LERROR), ipa_log_subsys_name(SESIPA), ipa_log_level_name(LDEBUG));
	printf("                       subsystems:");
	for (unsigned int i = 0; i < _NUM_LOG_SUBSYS; i++)
		printf(" %s", ipa_log_subsys_name(i));
	printf("\n                       levels:");
	for (unsigned int i = 0; i < _NUM_LOG_LEVEL; i++)
		printf(" %s", ipa_log_level_name(i));
	printf("\n");
	printf(" -E .................. emulate IoT eUICC (compatibility mode to use consumer eUICCs)\n");
	printf(" -1 .................. force the IPAd to process only one eUICC package (debug, use with caution)\n");
	printf("\n");
	printf(" ES10b triggers (one-shot; run once against the eUICC, then exit --\n");
	printf(" a real device daemon calls the matching ipa_* API from onomondo/ipad.h):\n");
	printf(" -R .................. set refresh_flag for the trigger below (request UICC REFRESH)\n");
	printf(" -i .................. ImmediateEnable the configured profile\n");
	printf(" -F .................. ExecuteFallbackMechanism (swap to the Fallback Profile)\n");
	printf(" -b .................. ReturnFromFallback (back to the operational profile)\n");
	printf(" -X .................. EnableEmergencyProfile\n");
	printf(" -x .................. DisableEmergencyProfile\n");
	printf(" -G .................. GetConnectivityParameters (print httpParams)\n");
	printf(" -D FQDN ............. SetDefaultDpAddress to the given SM-DP+ FQDN\n");
}

struct ipa_buf *load_ber_from_file(char *dir, char *file)
{
	char path[PATH_MAX] = { 0 };
	FILE *ber_file = NULL;
	struct ipa_buf *ber = NULL;
	size_t ber_size;
	int path_len;

	/* Bounds-checked path build: an over-long operator-supplied path must not
	 * overflow path[] (the old strcpy/strcat had no bound). */
	path_len = snprintf(path, sizeof(path), "%s%s", dir ? dir : "", file);
	if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
		IPA_LOGP(SMAIN, LERROR, "BER file path too long\n");
		return NULL;
	}

	/* Missing/unreadable file is an operator error, not an assertion: return
	 * NULL so the caller can report and exit cleanly (assert is a no-op under
	 * -DNDEBUG anyway). */
	ber_file = fopen(path, "r");
	if (!ber_file) {
		IPA_LOGP(SMAIN, LERROR, "cannot open BER file %s\n", path);
		return NULL;
	}

	fseek(ber_file, 0L, SEEK_END);
	ber_size = ftell(ber_file);
	rewind(ber_file);

	ber = ipa_buf_alloc(ber_size + 1);
	assert(ber);

	ber->len = fread(ber->data, sizeof(char), ber->data_len, ber_file);
	fclose(ber_file);
	IPA_LOGP(SMAIN, LINFO, "loaded BER data from file %s, size: %zu\n", path, ber->len);
	return ber;
}

struct ipa_buf *load_nvstate_from_file(char *path)
{
	FILE *file_ptr = NULL;
	struct ipa_buf *nvstate = NULL;
	size_t file_size;

	file_ptr = fopen(path, "r");
	if (!file_ptr) {
		IPA_LOGP(SMAIN, LERROR, "unable to load nvstate from file %s -- a new nvstate will be created.\n",
			 path);
		return NULL;
	}

	fseek(file_ptr, 0L, SEEK_END);
	file_size = ftell(file_ptr);
	rewind(file_ptr);

	nvstate = ipa_buf_alloc(file_size);
	assert(nvstate);

	nvstate->len = fread(nvstate->data, sizeof(char), nvstate->data_len, file_ptr);
	fclose(file_ptr);
	IPA_LOGP(SMAIN, LINFO, "loaded nvstate from file %s, size: %zu\n", path, nvstate->data_len);

	return nvstate;
}

void save_nvstate_to_file(char *path, struct ipa_buf *nvstate)
{
	FILE *file_ptr = NULL;

	file_ptr = fopen(path, "w");
	if (!file_ptr) {
		IPA_LOGP(SMAIN, LERROR, "unable to save nvstate from file %s!\n", path);
		return;
	}

	fwrite(nvstate->data, sizeof(char), nvstate->data_len, file_ptr);
	fclose(file_ptr);
	IPA_LOGP(SMAIN, LINFO, "saved nvstate to file %s, size: %zu\n", path, nvstate->data_len);
}

static void sig_usr1(int signum)
{
	running = false;
}

/* One-shot ES10b trigger actions selectable from the command line.  These map
 * 1:1 to the public ipa_* trigger API in onomondo/ipad.h and are meant as a
 * reference / debugging harness for the wiring a real device daemon would do. */
enum getopt_action {
	ACTION_NONE = 0,
	ACTION_IMMEDIATE_ENABLE,
	ACTION_EXECUTE_FALLBACK,
	ACTION_RETURN_FROM_FALLBACK,
	ACTION_ENABLE_EMERGENCY,
	ACTION_DISABLE_EMERGENCY,
	ACTION_GET_CONN_PARAMS,
	ACTION_SET_DEFAULT_DP,
};

/* Run a single ES10b trigger action against the eUICC and report the outcome.
 * Returns the negative transport error, or 0 once the command was delivered
 * (the eUICC's own status code, ok or not, is logged). */
static int run_es10b_trigger(struct ipa_context *ctx, enum getopt_action action, const char *default_dp, bool refresh)
{
	int rc = 0;

	switch (action) {
	case ACTION_IMMEDIATE_ENABLE:
		rc = ipa_immediate_enable(ctx, refresh);
		break;
	case ACTION_EXECUTE_FALLBACK:
		rc = ipa_execute_fallback(ctx, refresh);
		break;
	case ACTION_RETURN_FROM_FALLBACK:
		rc = ipa_return_from_fallback(ctx, refresh);
		break;
	case ACTION_ENABLE_EMERGENCY:
		rc = ipa_enable_emergency_profile(ctx, refresh);
		break;
	case ACTION_DISABLE_EMERGENCY:
		rc = ipa_disable_emergency_profile(ctx, refresh);
		break;
	case ACTION_GET_CONN_PARAMS: {
		struct ipa_connectivity_params *p = ipa_get_connectivity_params(ctx);
		if (!p) {
			IPA_LOGP(SMAIN, LERROR, "GetConnectivityParameters failed\n");
			return -EINVAL;
		}
		if (p->http_params)
			IPA_LOGP(SMAIN, LINFO, "connectivity httpParams (%zu bytes): %s\n",
				 p->http_params_len, ipa_hexdump(p->http_params, p->http_params_len));
		else
			IPA_LOGP(SMAIN, LINFO, "connectivity parameters: no httpParams present\n");
		ipa_connectivity_params_free(p);
		return 0;
	}
	case ACTION_SET_DEFAULT_DP:
		if (!default_dp) {
			IPA_LOGP(SMAIN, LERROR, "-D requires a default SM-DP+ FQDN argument\n");
			return -EINVAL;
		}
		rc = ipa_set_default_dp_addr(ctx, default_dp);
		break;
	default:
		return 0;
	}

	if (rc < 0)
		IPA_LOGP(SMAIN, LERROR, "ES10b trigger failed (transport error %d)\n", rc);
	else
		IPA_LOGP(SMAIN, LINFO, "ES10b trigger delivered, eUICC status code %d\n", rc);
	return rc < 0 ? rc : 0;
}

int main(int argc, char **argv)
{
	struct ipa_config cfg = { 0 };
	struct ipa_context *ctx = NULL;
	int opt;
	int rc;
	char *getopt_initial_eim_cfg_file = NULL;
	bool getopt_euicc_memory_reset = false;
	char *getopt_nvstate_path = DEFAULT_NVSTATE_PATH;
	struct ipa_buf *nvstate_load = NULL;
	struct ipa_buf *nvstate_save = NULL;
	bool getopt_one_euicc_pkg_only = false;
	enum getopt_action getopt_action = ACTION_NONE;
	char *getopt_default_dp = NULL;
	uint8_t getopt_imei[IPA_LEN_IMEI];

	signal(SIGUSR1, sig_usr1);

	printf("IPAd!\n");

	/* Populate configuration with default values */
	cfg.reader_num = DEFAULT_READER_NUMBER;
	cfg.euicc_channel = DEFAULT_CHANNEL_NUMBER;
	ipa_binary_from_hexstr(cfg.tac, sizeof(cfg.tac), DEFAULT_TAC);
	cfg.esipa_req_retries = DEFAULT_ESIPA_REQ_RETRIES;

	/* Overwrite configuration values with user defined parameters */
	while (1) {
		opt = getopt(argc, argv, "ht:M:e:r:c:f:mn:C:SIELl:d:y:a1RiFbXxGD:");
		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 't':
			ipa_binary_from_hexstr(cfg.tac, sizeof(cfg.tac), optarg);
			break;
		case 'L':
			ipa_log_set_print_source(true);
			break;
		case 'l':
		case 'd':
			if (parse_log_level_opt(optarg, opt == 'd') < 0)
				exit(1);
			break;
		case 'M':
			if (strlen(optarg) != IPA_LEN_IMEI * 2) {
				IPA_LOGP(SMAIN, LERROR, "-M expects %d hex digits (IMEI as Octet8)\n",
					 IPA_LEN_IMEI * 2);
				return -EINVAL;
			}
			ipa_binary_from_hexstr(getopt_imei, sizeof(getopt_imei), optarg);
			cfg.imei = getopt_imei;
			break;
		case 'e':
			cfg.preferred_eim_id = optarg;
			break;
		case 'r':
			cfg.reader_num = atoi(optarg);
			break;
		case 'c':
			cfg.euicc_channel = atoi(optarg);
			break;
		case 'f':
			getopt_initial_eim_cfg_file = optarg;
			break;
		case 'm':
			getopt_euicc_memory_reset = true;
			break;
		case 'n':
			getopt_nvstate_path = optarg;
			break;
		case 'C':
			cfg.eim_cabundle = optarg;
			break;
		case 'S':
			cfg.eim_disable_ssl = true;
			break;
		case 'I':
			cfg.eim_disable_ssl_verif = true;
			break;
		case 'E':
			cfg.iot_euicc_emu_enabled = true;
			break;
		case 'y':
			cfg.esipa_req_retries = atoi(optarg);
			break;
		case 'a':
			cfg.prfle_inst_consent_cb = prfle_inst_consent;
			break;
		case '1':
			getopt_one_euicc_pkg_only = true;
			break;
		case 'R':
			cfg.refresh_flag = true;
			break;
		case 'i':
			getopt_action = ACTION_IMMEDIATE_ENABLE;
			break;
		case 'F':
			getopt_action = ACTION_EXECUTE_FALLBACK;
			break;
		case 'b':
			getopt_action = ACTION_RETURN_FROM_FALLBACK;
			break;
		case 'X':
			getopt_action = ACTION_ENABLE_EMERGENCY;
			break;
		case 'x':
			getopt_action = ACTION_DISABLE_EMERGENCY;
			break;
		case 'G':
			getopt_action = ACTION_GET_CONN_PARAMS;
			break;
		case 'D':
			getopt_action = ACTION_SET_DEFAULT_DP;
			getopt_default_dp = optarg;
			break;
		default:
			printf("unhandled option: %c!\n", opt);
			break;
		};
	}

	/* Display current config */
	printf("parameter:\n");
	printf(" nvstate path: %s\n", getopt_nvstate_path);
	printf(" preferred_eim_id = %s\n", cfg.preferred_eim_id ? cfg.preferred_eim_id : "(first configured eIM)");
	printf(" reader_num = %d\n", cfg.reader_num);
	printf(" euicc_channel = %d\n", cfg.euicc_channel);
	if (cfg.eim_cabundle)
		printf(" eim_cabundle = %s\n", cfg.eim_cabundle);
	printf(" eim_disable_ssl = %d\n", cfg.eim_disable_ssl);
	printf(" eim_disable_ssl_verif = %d\n", cfg.eim_disable_ssl_verif);
	printf(" tac = %s\n", ipa_hexdump(cfg.tac, sizeof(cfg.tac)));
	if (cfg.imei)
		printf(" imei = %s\n", ipa_hexdump(cfg.imei, IPA_LEN_IMEI));
	printf(" iot_euicc_emu_enabled = %u\n", cfg.iot_euicc_emu_enabled);
	printf(" esipa_req_retries = %u\n", cfg.esipa_req_retries);
	printf(" refresh_flag = %u\n", cfg.refresh_flag);
	printf("\n");

	if (cfg.eim_cabundle) {
		rc = access(cfg.eim_cabundle, R_OK);
		if (rc < 0) {
			IPA_LOGP(SMAIN, LERROR, "error accessing CA bundle %s: %s\n", cfg.eim_cabundle,
				 strerror(errno));
			goto leave;
		}
	}

	/* Create a new IPA context */
	nvstate_load = load_nvstate_from_file(getopt_nvstate_path);
	ctx = ipa_new_ctx(&cfg, nvstate_load);
	if (!ctx) {
		IPA_LOGP(SMAIN, LERROR, "cannot create context!\n");
		rc = -EINVAL;
		goto leave;
	}

	/* Initialize IPA */
	IPA_LOGP(SMAIN, LINFO, "-----------------------------8<-----------------------------\n");
	rc = ipa_init(ctx);
	if (rc < 0) {
		IPA_LOGP(SMAIN, LERROR, "IPAd initialization failed!\n");
		rc = -EINVAL;
		goto leave;
	}

	if (getopt_initial_eim_cfg_file) {
		/* Load initial eIM configuration */
		struct ipa_buf *eim_cfg = load_ber_from_file(NULL, getopt_initial_eim_cfg_file);
		if (!eim_cfg) {
			IPA_LOGP(SMAIN, LERROR, "failed to load initial eIM configuration\n");
			rc = -EINVAL;
			goto leave;
		}
		ipa_add_init_eim_cfg(ctx, eim_cfg);
		IPA_FREE(eim_cfg);
	} else if (getopt_euicc_memory_reset) {
		/* Perform an eUICC memory reset */
		ipa_euicc_mem_rst(ctx, true, true, true, true, true);
	} else if (getopt_action != ACTION_NONE) {
		/* Fire a single ES10b trigger (fallback / emergency / connectivity /
		 * default-DP / immediate-enable) and exit -- these do not need the eIM. */
		rc = run_es10b_trigger(ctx, getopt_action, getopt_default_dp, cfg.refresh_flag);
		if (rc < 0)
			rc = -EINVAL;
	} else {
		IPA_LOGP(SMAIN, LINFO, "-----------------------------8<-----------------------------\n");
		rc = eim_init(ctx);
		if (rc < 0) {
			IPA_LOGP(SMAIN, LERROR, "eIM initialization failed!\n");
			rc = -EINVAL;
			goto leave;
		}

		while (running) {
			IPA_LOGP(SMAIN, LINFO, "-----------------------------8<-----------------------------\n");
			rc = ipa_poll(ctx);

			switch (rc) {
			case IPA_POLL_AGAIN_WHEN_ONLINE:
				/* ipa_poll asks us to wait with the next poll cycle until we have a stable IP
				 * connection. In this example we assume that IP connectivity is always available. */
				IPA_LOGP(SMAIN, LINFO, "poll cycle continues normally (profile change)\n");
				rc = 0;
				break;
			case IPA_POLL_AGAIN:
				/* ipa_poll asks us to continue polling normally */
				rc = 0;
				if (getopt_one_euicc_pkg_only) {
					IPA_LOGP(SMAIN, LINFO, "forcefully stopping poll cycle upon user decision!\n");
					goto leave;
				} else {
					IPA_LOGP(SMAIN, LINFO, "poll cycle continues normally\n");
					break;
				}
			case IPA_POLL_AGAIN_LATER:
				/* ipa_poll tells us that we may poll less frequently, so just exit. */
				IPA_LOGP(SMAIN, LERROR, "poll cycle ends normally\n");
				rc = 0;
				goto leave;
			default:
				/* We got a negative return code from ipa_poll. This means something does not work
				 * normally. In a productive setup we would continue calling ipa_poll a few more times
				 * to see if the cause is a temporary problem. After that we would free the context
				 * using ipa_free_ctx and start over. */
				IPA_LOGP(SMAIN, LERROR, "poll cycle ends due to error (%d)\n", rc);
				rc = -EINVAL;
				goto leave;
			}
		}
	}

leave:
	IPA_LOGP(SMAIN, LINFO, "-----------------------------8<-----------------------------\n");
	nvstate_save = ipa_free_ctx(ctx);
	if (nvstate_save)
		save_nvstate_to_file(getopt_nvstate_path, nvstate_save);
	IPA_FREE(nvstate_load);
	IPA_FREE(nvstate_save);
	return rc;
}
