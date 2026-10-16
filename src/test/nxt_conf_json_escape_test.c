/*
 * Copyright (C) FreeUnit
 */


#include <nxt_main.h>
#include <nxt_conf.h>
#include "nxt_tests.h"


/*
 * The JSON string escaper behind the structured access log (freeunit-exp #70).
 *
 * The escaped form of a logged value is the contract a log consumer parses, so
 * it is pinned here byte for byte.  The frozen data file and its reasoning are
 * data/json-access-log-escape-vectors.json; this test is its C half, written
 * against the public serializer rather than the static escaper so it exercises
 * the path a record actually takes: nxt_conf_set_member_string() then
 * nxt_conf_json_print().
 *
 * The rows today:
 *
 *   "        -> \"        the quote must not end the JSON string (#376 class)
 *   \        -> \\        the backslash must not start an escape
 *   0x08     -> \b        the five short escapes
 *   0x0C     -> \f
 *   0x0A     -> \n
 *   0x0D     -> \r
 *   0x09     -> \t
 *   0x01     -> \u0001    every other byte <= 0x1F, uppercase hex
 *   0x1F     -> \u001F    the top of that range
 *   0x7F     -> 0x7F raw  DEL is not a JSON metacharacter
 *   "/"      -> "/"       the forward slash is not escaped
 *   valid multibyte       copied byte for byte
 *
 * Invalid UTF-8 is deliberately absent: the sink owns it, not the escaper
 * (nxt_router_access_log.c:337-351 calls nxt_utf8_sanitize() before the value
 * reaches the serializer).  A row here that fed raw invalid bytes to
 * nxt_conf_set_member_string() would be testing a call the log path never makes,
 * and the serializer is also what writes state/conf.json, where the bytes are
 * the operator's and must round-trip exactly.
 */
nxt_int_t
nxt_conf_json_escape_test(nxt_thread_t *thr)
{
    nxt_mp_t            *mp;
    nxt_str_t           name, value;
    nxt_uint_t          i;
    nxt_conf_value_t    *object;
    u_char              *p, buf[256];
    static const struct {
        const char  *value;
        const char  *json;      /* the whole record: {"v":"<escaped>"} */
        const char  *why;
    } cases[] = {
        { "plain",
          "{\"v\":\"plain\"}",
          "nothing to escape" },

        { "a\"b",
          "{\"v\":\"a\\\"b\"}",
          "a quote inside the value" },

        { "a\\b",
          "{\"v\":\"a\\\\b\"}",
          "a backslash inside the value" },

        { "\\\"",
          "{\"v\":\"\\\\\\\"\"}",
          "backslash then quote: neither may leak" },

        { "a/b",
          "{\"v\":\"a/b\"}",
          "the forward slash is not escaped" },

        { "\b\f\n\r\t",
          "{\"v\":\"\\b\\f\\n\\r\\t\"}",
          "the five short escapes, in order" },

        { "\x01",
          "{\"v\":\"\\u0001\"}",
          "the long form for the rest of the C0 range" },

        { "\x0b",
          "{\"v\":\"\\u000B\"}",
          "uppercase hex: a lower-case expectation is wrong" },

        { "\x1f",
          "{\"v\":\"\\u001F\"}",
          "the top of the long-form range" },

        { "\x7f",
          "{\"v\":\"\x7f\"}",
          "DEL is above 0x1F and is copied raw" },

        { "\xc3\xa9",
          "{\"v\":\"\xc3\xa9\"}",
          "a valid two-byte sequence is copied" },

        { "\xf0\x9f\x98\x80",
          "{\"v\":\"\xf0\x9f\x98\x80\"}",
          "a valid four-byte sequence is copied" },

        /*
         * U+2028 and U+2029 are valid JSON and are copied raw. They are line
         * terminators in JavaScript source, so a consumer that embeds a record
         * in a script sees a break JSON does not have -- but escaping them is a
         * client-hardening decision, not a JSON requirement, and the row exists
         * so that decision is testable rather than assumed.
         */
        { "\xe2\x80\xa8",
          "{\"v\":\"\xe2\x80\xa8\"}",
          "U+2028 is copied raw" },

        { "\xe2\x80\xa9",
          "{\"v\":\"\xe2\x80\xa9\"}",
          "U+2029 is copied raw" },

        { "",
          "{\"v\":\"\"}",
          "the empty value is a legal JSON string" },
    };

    nxt_memzero(buf, sizeof(buf));

    name.start = (u_char *) "v";
    name.length = 1;

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (mp == NULL) {
        return NXT_ERROR;
    }

    for (i = 0; i < nxt_nitems(cases); i++) {
        object = nxt_conf_create_object(mp, 1);
        if (object == NULL) {
            nxt_mp_destroy(mp);
            return NXT_ERROR;
        }

        value.start = (u_char *) cases[i].value;
        value.length = nxt_strlen(cases[i].value);

        nxt_conf_set_member_string(object, &name, &value, 0);

        p = nxt_conf_json_print(buf, object, NULL);

        /* The serializer returns the end of the record and does not terminate it. */
        NXT_TEST_CHECK(thr->log, (size_t) (p - buf) < sizeof(buf),
                       "JSON escape test: a %uz byte record does not fit the "
                       "%uz byte buffer", (size_t) (p - buf), sizeof(buf));

        *p = '\0';

        /*
         * The claim is a byte comparison of the whole record, not of a
         * substring: a row that expects "\u007F" for DEL, or lower-case hex,
         * must fail here rather than pass on partial credit.
         */
        NXT_TEST_CHECK(thr->log, nxt_strcmp(buf, cases[i].json) == 0,
                       "JSON escape test failed on \"%s\" (%s): got \"%s\", "
                       "expected \"%s\"",
                       cases[i].why, cases[i].value, buf, cases[i].json);

        nxt_memzero(buf, sizeof(buf));
    }

    nxt_mp_destroy(mp);

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "nxt_conf_json_escape_test() passed, %uz vectors",
                  nxt_nitems(cases));

    return NXT_OK;
}
