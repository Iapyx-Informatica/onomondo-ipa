# Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

# Documentation check rather than a code one: it reads MIGRATION.md and the sources, builds nothing,
# and so has no target.  The source tree is passed in because the sources are what it greps.
add_test(NAME cr_markers_test
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/cr_markers_test.sh ${PROJECT_SOURCE_DIR})
