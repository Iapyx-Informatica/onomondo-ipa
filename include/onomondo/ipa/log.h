/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

/*! macro to print a log line.
 *  \param[in] subsys log subsystem identifier.
 *  \param[in] level log level identifier.
 *  \param[in] fmt formtstring.
 *  \param[in] args formatstring arguments. */
#define IPA_LOGP(subsys, level, fmt, args...) \
	ipa_logp(subsys, level, __FILE__, __LINE__, fmt, ## args)

void ipa_logp(uint32_t subsys, uint32_t level, const char *file, int line,
	      const char *format, ...)
    __attribute__((format(printf, 5, 6)));

/*! Print the source file and line that produced each log line, as "(file.c:123)".
 *
 *  Off by default, for two reasons. The unit tests compare log output byte for byte against golden files, and
 *  __FILE__ holds whatever path the compiler was handed -- an absolute one in this project -- so the location
 *  is only reproducible because just the last path component is printed.
 *
 *  \param[in] enable true to include the source location, false to leave it out. */
void ipa_log_set_print_source(bool enable);

enum log_subsys {
	SMAIN,
	SHTTP,
	SSCARD,
	SIPA,
	SES10X,
	SES10B,
	SEUICC,
	SESIPA,
	_NUM_LOG_SUBSYS
};

enum log_level {
	LERROR,
	LINFO,
	LDEBUG,
	_NUM_LOG_LEVEL
};

/* Runtime control of what gets logged. Each subsystem carries its own maximum level (LDEBUG for all of them
 * unless changed, i.e. nothing is filtered out) and its own enable flag; a log line is printed only when the
 * subsystem is enabled and the line's level is at or below the subsystem's maximum. */

void ipa_log_set_level(enum log_subsys subsys, enum log_level level);
void ipa_log_set_level_all(enum log_level level);
enum log_level ipa_log_get_level(enum log_subsys subsys);

void ipa_log_set_subsys_enabled(enum log_subsys subsys, bool enable);
bool ipa_log_subsys_enabled(enum log_subsys subsys);

bool ipa_log_check(enum log_subsys subsys, enum log_level level);

/* Name lookups. These exist so that a caller that has to turn a user-supplied string into a subsystem or a level
 * -- the command line of the sample application, a configuration file -- does not need a second copy of the name
 * tables, which would drift the first time a subsystem is added. */

int ipa_log_subsys_by_name(const char *name);
int ipa_log_level_by_name(const char *name);
const char *ipa_log_subsys_name(enum log_subsys subsys);
const char *ipa_log_level_name(enum log_level level);
