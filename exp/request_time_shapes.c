/*
 * request_time: integer milliseconds against decimal seconds, measured.
 *
 * Experiment for freeunit-exp #70 (decision D4) and #74. It builds both shapes
 * with the public configuration API only -- no private struct access, no new
 * API -- and prints the whole record each one produces, so the difference is a
 * measurement rather than a description.
 *
 *   integer shape: nxt_conf_set_member_integer(object, name, ms, index)
 *   decimal shape: nxt_conf_json_parse_str(mp, "0.041"), then serialized
 *
 * The decimal shape goes through the parser because that is the only public
 * producer of NXT_CONF_VALUE_NUMBER, and the parser accepts a bare number as a
 * document. That is itself the finding: the integer shape needs no new API, the
 * decimal shape needs one.
 *
 * This file is an experiment, deliberately not part of the test suite.
 */

#include <nxt_main.h>
#include <nxt_conf.h>
#include <stdio.h>


static const nxt_msec_t  cases[] = { 0, 41, 999, 1000, 60000, 3600000 };


int
main(void)
{
    nxt_uint_t              i;
    nxt_mp_t                *mp;
    nxt_str_t               name, decimal;
    nxt_conf_value_t        *object, *parsed;
    nxt_conf_json_error_t   err;
    u_char                  want[32];

    name.start = (u_char *) "v";
    name.length = 1;

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (mp == NULL) {
        return 1;
    }

    printf("%-9s %-14s %-12s %-14s %s\n",
           "ms", "integer", "decimal text", "decimal", "note");
    printf("%-9s %-14s %-12s %-14s %s\n",
           "--------", "---------", "------------", "---------", "----");

    for (i = 0; i < nxt_nitems(cases); i++) {
        u_char  ibuf[64], dbuf[64], note[80];

        note[0] = '\0';

        object = nxt_conf_create_object(mp, 1);
        if (object == NULL) {
            return 1;
        }

        nxt_conf_set_member_integer(object, &name, cases[i], 0);
        *nxt_conf_json_print(ibuf, object, NULL) = '\0';

        /*
         * The decimal text for the same instant is exactly what the current
         * format prints (src/nxt_http_variables.c:237-260), so a decimal field
         * would carry the same digits a consumer sees today.
         */
        decimal.start = want;
        decimal.length = nxt_sprintf(want, want + sizeof(want), "%T.%03M",
                                     (nxt_time_t) cases[i] / 1000,
                                     cases[i] % 1000) - want;

        nxt_memzero(&want[decimal.length], sizeof(want) - decimal.length);

        nxt_memzero(&err, sizeof(err));

        parsed = nxt_conf_json_parse(mp, decimal.start,
                                     decimal.start + decimal.length, &err);

        if (parsed == NULL) {
            nxt_sprintf(note, note + sizeof(note),
                        "REJECTED at offset %ld%s%s",
                        (long) (err.pos - decimal.start),
                        err.detail ? ": " : "",
                        err.detail ? (char *) err.detail : "");
            dbuf[0] = '\0';

        } else {
            *nxt_conf_json_print(dbuf, parsed, NULL) = '\0';
        }

        printf("%-9lu %-14s %-12s %-14s %s\n", (unsigned long) cases[i],
               ibuf, want, dbuf, note);
    }

    nxt_mp_destroy(mp);

    return 0;
}
