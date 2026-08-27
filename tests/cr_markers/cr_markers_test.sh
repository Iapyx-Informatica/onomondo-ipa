#!/bin/sh
# Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only
#
# MIGRATION.md states the rule this checks: "Changes carry inline markers so each one is traceable
# back to the spec".  Every change request listed under "What shipped" is therefore expected to be
# findable in the tree by its own name.
#
# The rule was not being enforced, and two rows had drifted: CR12011R00 was listed as shipped while
# nothing implemented it, and CR12013R00 had shipped without a marker.  From the outside those two
# look identical -- grep finds nothing either way -- which is exactly what this test exists to stop.
#
# A CR that genuinely needs no code says so in its own Outcome column ("eUICC-side only", "out of
# scope", and so on) and is skipped.  Everything else must have at least one marker.
#
# Usage: cr_markers_test.sh <source tree root>

set -u

root="${1:?usage: cr_markers_test.sh <source tree root>}"
migration="$root/MIGRATION.md"
rc=0

if [ ! -f "$migration" ]; then
	echo "FAIL: $migration not found"
	exit 1
fi

# The change request table: rows of "| CRxxxxxRxx | sections | outcome |".
# A digit after "CR" keeps the table's own header row ("| CR | Sections | Outcome |") out.
crs=$(sed -n 's/^| *\(CR[0-9][0-9A-Za-z]*\) *|.*/\1/p' "$migration")

if [ -z "$crs" ]; then
	echo "FAIL: no change request rows found in $migration -- has the table moved?"
	exit 1
fi

for cr in $crs; do
	n=$(grep -rl "$cr" "$root/src" "$root/include" "$root/asn1" \
	    --include='*.c' --include='*.h' --include='*.asn' 2>/dev/null | wc -l)
	if [ "$n" -gt 0 ]; then
		printf 'ok   %-12s %s file(s)\n' "$cr" "$n"
		continue
	fi

	# No marker.  That is only acceptable where the row itself says the change needed no code here,
	# which is checked second so that a row saying so and carrying markers anyway still reports them.
	outcome=$(sed -n "s/^| *$cr *|[^|]*| *\(.*[^ ]\) *|.*/\1/p" "$migration")
	case "$outcome" in
	*"eUICC-side only"*|*"out of scope"*|*"Out of scope"*)
		printf 'ok   %-12s no marker, and the row says none was needed\n' "$cr"
		;;
	*)
		printf 'FAIL %-12s listed as shipped, but no file carries the marker\n' "$cr"
		rc=1
		;;
	esac
done

if [ $rc -ne 0 ]; then
	echo
	echo "A change request in MIGRATION.md's \"What shipped\" table has no marker in the tree."
	echo "Either add the marker where the change was made, or move the row to \"What remains\"."
fi
exit $rc
