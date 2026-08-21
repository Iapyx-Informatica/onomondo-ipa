/*
 * Copyright (c) 2025 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/utils.h>
#include "utils.h"

/* One bit per subsystem, set when the subsystem is enabled. A disabled subsystem prints nothing at all, which is
 * something a per-subsystem maximum level cannot express: the lowest level, LERROR, still prints errors. */
static uint32_t subsys_mask = 0xffffffff;

/* Maximum level each subsystem prints, see ipa_log_set_level(). LDEBUG (the highest) for all of them by default,
 * so that an application that never calls the setters gets every log line, as it did before the levels became
 * settable. */
static uint32_t subsys_lvl[_NUM_LOG_SUBSYS] = {
	[SMAIN] = LDEBUG,
	[SHTTP] = LDEBUG,
	[SSCARD] = LDEBUG,
	[SIPA] = LDEBUG,
	[SES10X] = LDEBUG,
	[SES10B] = LDEBUG,
	[SEUICC] = LDEBUG,
	[SESIPA] = LDEBUG,
};

static const char *subsys_str[_NUM_LOG_SUBSYS] = {
	[SMAIN] = "MAIN",
	[SHTTP] = "HTTP",
	[SSCARD] = "SCARD",
	[SIPA] = "IPA",
	[SES10X] = "ES10x",
	[SES10B] = "ES10b",
	[SEUICC] = "eUICC",
	[SESIPA] = "ESIPA",
};

/* Whether each log line carries the source location, see ipa_log_set_print_source(). */
static bool print_source;

/*! Print the source file and line that produced each log line. */
void ipa_log_set_print_source(bool enable)
{
	print_source = enable;
}

/* __FILE__ expands to the path the compiler was given, which for this project is an absolute one. Only the last
 * component belongs in a log line: the rest says where the tree happened to be built, which is noise to the
 * reader and would make the output differ from one build machine to the next. */
static const char *source_file_name(const char *file)
{
	const char *slash;

	if (!file)
		return "?";

	slash = strrchr(file, '/');
	return slash ? slash + 1 : file;
}

static const char *level_str[_NUM_LOG_LEVEL] = {
	[LERROR] = "ERROR",
	[LINFO] = "INFO",
	[LDEBUG] = "DEBUG",
};

/*! Set the maximum log level of a single subsystem.
 *  \param[in] subsys log subsystem identifier.
 *  \param[in] level highest level the subsystem still prints (LERROR prints least, LDEBUG prints everything). */
void ipa_log_set_level(enum log_subsys subsys, enum log_level level)
{
	if (subsys >= _NUM_LOG_SUBSYS || level >= _NUM_LOG_LEVEL)
		return;
	subsys_lvl[subsys] = level;
}

/*! Set the maximum log level of every subsystem at once.
 *  \param[in] level highest level the subsystems still print. */
void ipa_log_set_level_all(enum log_level level)
{
	unsigned int i;

	for (i = 0; i < _NUM_LOG_SUBSYS; i++)
		ipa_log_set_level(i, level);
}

/*! Get the maximum log level of a subsystem.
 *  \param[in] subsys log subsystem identifier.
 *  \returns highest level the subsystem still prints (LERROR for an out of range subsystem). */
enum log_level ipa_log_get_level(enum log_subsys subsys)
{
	if (subsys >= _NUM_LOG_SUBSYS)
		return LERROR;
	return subsys_lvl[subsys];
}

/*! Enable or disable a subsystem entirely.
 *  \param[in] subsys log subsystem identifier.
 *  \param[in] enable false to drop every line of this subsystem, errors included. */
void ipa_log_set_subsys_enabled(enum log_subsys subsys, bool enable)
{
	if (subsys >= _NUM_LOG_SUBSYS)
		return;

	if (enable)
		subsys_mask |= (1 << subsys);
	else
		subsys_mask &= ~(1 << subsys);
}

/*! Check whether a subsystem is enabled.
 *  \param[in] subsys log subsystem identifier.
 *  \returns true when the subsystem prints at all, see ipa_log_set_subsys_enabled(). */
bool ipa_log_subsys_enabled(enum log_subsys subsys)
{
	if (subsys >= _NUM_LOG_SUBSYS)
		return false;
	return (subsys_mask & (1 << subsys)) != 0;
}

/*! Check whether a log line would be printed.
 *
 *  ipa_logp() applies this to every line it is handed, so a caller does not need to. It is worth asking in advance
 *  only when producing the line is itself expensive -- the dump helpers decode, format and allocate before they
 *  have anything to log, and all of that is wasted if the result is dropped here.
 *
 *  \param[in] subsys log subsystem identifier.
 *  \param[in] level log level identifier.
 *  \returns true when a line logged with these parameters is printed. */
bool ipa_log_check(enum log_subsys subsys, enum log_level level)
{
	if (subsys >= _NUM_LOG_SUBSYS || level >= _NUM_LOG_LEVEL)
		return false;
	if (!ipa_log_subsys_enabled(subsys))
		return false;
	return level <= ipa_log_get_level(subsys);
}

/* Compare a user-supplied name against a table entry. The trailing NUL is part of the comparison, so that an
 * abbreviation ("ES10") does not match a longer name ("ES10x"): the two ES10 subsystems differ in one character
 * and silently picking one of them would be worse than rejecting the input. */
static bool name_matches(const char *name, const char *table_entry)
{
	return ipa_cmp_case_insensitive(name, table_entry, strlen(table_entry) + 1) == 0;
}

/*! Look up a log subsystem by name, case insensitively.
 *  \param[in] name subsystem name as printed in the log, e.g. "ES10b".
 *  \returns the enum log_subsys value, -1 when there is no subsystem of that name. */
int ipa_log_subsys_by_name(const char *name)
{
	unsigned int i;

	if (!name)
		return -1;

	for (i = 0; i < _NUM_LOG_SUBSYS; i++) {
		if (name_matches(name, subsys_str[i]))
			return (int)i;
	}

	return -1;
}

/*! Look up a log level by name, case insensitively.
 *  \param[in] name level name as printed in the log, e.g. "debug".
 *  \returns the enum log_level value, -1 when there is no level of that name. */
int ipa_log_level_by_name(const char *name)
{
	unsigned int i;

	if (!name)
		return -1;

	for (i = 0; i < _NUM_LOG_LEVEL; i++) {
		if (name_matches(name, level_str[i]))
			return (int)i;
	}

	return -1;
}

/*! Get the name of a log subsystem.
 *  \param[in] subsys log subsystem identifier.
 *  \returns the name as printed in the log, NULL when the subsystem is out of range. */
const char *ipa_log_subsys_name(enum log_subsys subsys)
{
	if (subsys >= _NUM_LOG_SUBSYS)
		return NULL;
	return subsys_str[subsys];
}

/*! Get the name of a log level.
 *  \param[in] level log level identifier.
 *  \returns the name as printed in the log, NULL when the level is out of range. */
const char *ipa_log_level_name(enum log_level level)
{
	if (level >= _NUM_LOG_LEVEL)
		return NULL;
	return level_str[level];
}

/*! print a log line (called by IPA_LOGP, do not call directly).
 *  \param[in] subsys log subsystem identifier.
 *  \param[in] level log level identifier.
 *  \param[in] file source file name.
 *  \param[in] line source file line.
 *  \param[in] format format string (followed by arguments). */
void ipa_logp(uint32_t subsys, uint32_t level, const char *file, int line, const char *format, ...)
{
	va_list ap;

	assert(subsys < IPA_ARRAY_SIZE(subsys_lvl));

	if (!ipa_log_check(subsys, level))
		return;

	fprintf(stderr, "%8s %8s ", subsys_str[subsys], level_str[level]);

	/* Off unless asked for: the unit tests compare log output against golden .err files, which any extra
	 * column would upset. */
	if (print_source)
		fprintf(stderr, "(%s:%d) ", source_file_name(file), line);

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}
