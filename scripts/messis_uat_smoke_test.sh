#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://messis.ads-ai.in}"
TEST_USER_ID="${TEST_USER_ID:-}"
TEST_PASSCODE="${TEST_PASSCODE:-}"
TEST_CREDENTIAL_FILE="${TEST_CREDENTIAL_FILE:-}"

if [[ -n "$TEST_CREDENTIAL_FILE" ]]; then
    [[ -r "$TEST_CREDENTIAL_FILE" ]] || {
        echo "FAIL credential file is not readable"
        exit 2
    }
    TEST_USER_ID="${TEST_USER_ID:-$(sed -nE 's/^(USER ID|USER_ID)[[:space:]]*[:=][[:space:]]*([^[:space:]]+).*/\2/Ip' "$TEST_CREDENTIAL_FILE" | sed -n '1p')}"
    TEST_PASSCODE="${TEST_PASSCODE:-$(sed -nE 's/^PASSCODE[[:space:]]*[:=][[:space:]]*([0-9]{6}).*/\1/Ip' "$TEST_CREDENTIAL_FILE" | sed -n '1p')}"
fi

if [[ -z "$TEST_USER_ID" || ! "$TEST_PASSCODE" =~ ^[0-9]{6}$ ]]; then
    echo "FAIL set TEST_USER_ID and TEST_PASSCODE, or TEST_CREDENTIAL_FILE"
    exit 2
fi

tmp_dir="$(mktemp -d /tmp/messis-uat-001.XXXXXX)"
case "$tmp_dir" in
    /tmp/messis-uat-001.*) ;;
    *) echo "FAIL unsafe temporary directory"; exit 2 ;;
esac
trap 'rm -rf -- "$tmp_dir"' EXIT

cookie_jar="$tmp_dir/cookies.txt"
failures=0

check_status() {
    local name="$1"
    local expected="$2"
    shift 2
    local actual
    actual="$(curl --silent --show-error --output "$tmp_dir/body" --write-out '%{http_code}' "$@")"
    if [[ "$actual" == "$expected" ]]; then
        echo "PASS $name ($actual)"
    else
        echo "FAIL $name expected=$expected actual=$actual"
        failures=$((failures + 1))
    fi
    if [[ "$actual" == "500" ]]; then
        echo "FAIL $name returned HTTP 500"
        failures=$((failures + 1))
    fi
}

check_status "login page" 200 "$BASE_URL/"
check_status "health" 200 "$BASE_URL/health"
check_status "static CSS" 200 "$BASE_URL/static/css/app.css"
check_status "signup page" 200 "$BASE_URL/auth/set-passcode"
check_status "unauthenticated dashboard redirect" 303 "$BASE_URL/dashboard"
check_status "unauthenticated farms redirect" 303 "$BASE_URL/farms"

check_status \
    "login POST" 303 \
    --cookie-jar "$cookie_jar" \
    --dump-header "$tmp_dir/login-headers" \
    --header "Origin: $BASE_URL" \
    --request POST \
    --data-urlencode "user_id=$TEST_USER_ID" \
    --data-urlencode "passcode=$TEST_PASSCODE" \
    "$BASE_URL/auth/login"

login_location="$(sed -nE 's/^[Ll]ocation:[[:space:]]*([^[:space:]\r]+).*/\1/p' "$tmp_dir/login-headers" | sed -n '1p')"
if [[ "$login_location" == "/dashboard" ]]; then
    echo "PASS login redirect target"
else
    echo "FAIL login redirect target is not dashboard"
    failures=$((failures + 1))
fi

if [[ -s "$cookie_jar" ]]; then
    echo "PASS session cookie issued"
else
    echo "FAIL session cookie not issued"
    failures=$((failures + 1))
fi

check_status "authenticated dashboard" 200 --cookie "$cookie_jar" "$BASE_URL/dashboard"
check_status "farms list" 200 --cookie "$cookie_jar" "$BASE_URL/farms"
cp "$tmp_dir/body" "$tmp_dir/farms.html"
check_status "farm create page" 200 --cookie "$cookie_jar" "$BASE_URL/farms/new"
check_status \
    "farm create validation" 422 \
    --cookie "$cookie_jar" \
    --header "Origin: $BASE_URL" \
    --request POST \
    --data-urlencode "name=" \
    --data-urlencode "location=UAT validation only" \
    --data-urlencode "acreage=-1" \
    --data-urlencode "total_trees=-1" \
    --data-urlencode "notes=" \
    "$BASE_URL/farms/new"

farm_path="$(grep -oE '/farms/[0-9]+' "$tmp_dir/farms.html" | sed -n '1p' || true)"
if [[ -n "$farm_path" ]]; then
    farm_id="${farm_path##*/}"
    check_status "farm detail" 200 --cookie "$cookie_jar" "$BASE_URL$farm_path"
    check_status "coconut tree list" 200 --cookie "$cookie_jar" "$BASE_URL/farms/$farm_id/trees"
    cp "$tmp_dir/body" "$tmp_dir/trees.html"
    check_status "coconut tree API" 200 --cookie "$cookie_jar" "$BASE_URL/api/farms/$farm_id/trees"

    tree_path="$(grep -oE "/farms/$farm_id/trees/[0-9]+" "$tmp_dir/trees.html" | sed -n '1p' || true)"
    if [[ -n "$tree_path" ]]; then
        tree_id="${tree_path##*/}"
        check_status "coconut tree detail" 200 --cookie "$cookie_jar" "$BASE_URL$tree_path"
        check_status "tree activity list" 200 --cookie "$cookie_jar" "$BASE_URL$tree_path/activities"
        check_status "tree activity API" 200 --cookie "$cookie_jar" "$BASE_URL/api/farms/$farm_id/trees/$tree_id/activities"
    else
        echo "SKIP tree detail/activity checks (test farm has no individual trees)"
    fi
else
    echo "SKIP farm/tree/activity detail checks (test owner has no farms)"
fi

check_status "logout" 303 --cookie "$cookie_jar" --cookie-jar "$cookie_jar" --header "Origin: $BASE_URL" --request POST "$BASE_URL/auth/logout"
check_status "session invalid after logout" 303 --cookie "$cookie_jar" "$BASE_URL/dashboard"

if (( failures > 0 )); then
    echo "PATCH-UAT-001 SMOKE TEST: FAIL ($failures failures)"
    exit 1
fi

echo "PATCH-UAT-001 SMOKE TEST: PASS"
