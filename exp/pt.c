#include <nxt_main.h>
#include <nxt_conf.h>
#include <stdio.h>

int main(void) {
    nxt_mp_t *mp = nxt_mp_create(1024, 128, 256, 32);
    const char *inputs[] = { "3600.000", "3600.00", "36000.000", "60.000", "0.041", "999999.999" };
    for (unsigned i = 0; i < sizeof(inputs)/sizeof(*inputs); i++) {
        nxt_str_t s; nxt_conf_json_error_t err;
        s.start = (u_char *) inputs[i]; s.length = nxt_strlen(inputs[i]);
        nxt_memzero(&err, sizeof(err));
        nxt_conf_value_t *v = nxt_conf_json_parse(mp, s.start, s.start + s.length, &err);
        if (v == NULL) {
            printf("%-12s PARSE FAILED  at offset %ld  detail=%s\n", inputs[i],
                   (long) (err.pos - s.start),
                   err.detail ? (char *) err.detail : "(none)");
        } else {
            u_char buf[64]; *nxt_conf_json_print(buf, v, NULL) = '\0';
            printf("%-12s OK  printed=%s\n", inputs[i], buf);
        }
    }
    return 0;
}
