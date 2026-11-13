/*
 * vbanhub cert - the hub's certificate authority for secure VBAN (called by the
 * init script, which LuCI calls). Files in the PKI directory (default
 * /etc/vbanhub/pki, override with VBANHUB_PKI):
 *
 *   ca.key  (0600) ca.crt     the network CA (ca.key absent = CA kept elsewhere)
 *   hub.key (0600) hub.crt    the hub's own identity; hub.req while waiting for an external CA
 *   issued/<serial>.crt       every certificate signed here (for the list / revocation)
 *   revoked                   one revoked serial per line (decimal)
 *
 * Commands (output is JSON or PEM text on stdout, errors on stderr, exit 1):
 *   status                               JSON summary
 *   init <ca name> <years> <hub name>    new CA + hub certificate (refuses if a CA exists)
 *   import <ca.crt> [ca.key] <hub name>  use an existing CA; without its key prints a hub request
 *   hub-cert <hub.crt>                   install the hub certificate signed by an external CA
 *   hub-renew <hub name> <days>          new hub certificate from the local CA key
 *   sign <request file> <days>           sign a device request, print the certificate
 *   revoke <serial>                      add to the revocation list
 *   export-ca                            print ca.crt
 *   reset                                delete the whole PKI directory content
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "vban/vban_secure.h"

static char g_dir[200];

static const char *pk(const char *name)
{
    static char p[2][300];
    static int i;
    i ^= 1;
    snprintf(p[i], sizeof p[i], "%.150s/%.120s", g_dir, name);
    return p[i];
}

static int exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static int fail(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    return 1;
}

static int read_text(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f)
        return -1;
    n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = 0;
    return (int)n;
}

static int load_pem(const char *path, const char *label, uint8_t *out, size_t len)
{
    char txt[4096];
    int n = read_text(path, txt, sizeof txt), r;
    if (n < 0)
        return -1;
    r = vban_pem_decode(label, txt, (size_t)n, out, len);
    memset(txt, 0, sizeof txt);
    return r == (int)len ? 0 : -1;
}

/* Write atomically (tmp + rename). mode 0600 for secrets. */
static int save_pem(const char *path, const char *label, const uint8_t *bin, size_t len, int secret)
{
    char pem[1024], tmp[320];
    int fd, n, ok;
    n = vban_pem_encode(label, bin, len, pem, sizeof pem);
    if (n < 0)
        return -1;
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    unlink(tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, secret ? 0600 : 0644);
    if (fd < 0)
        return -1;
    ok = write(fd, pem, (size_t)n) == n && fsync(fd) == 0;
    close(fd);
    memset(pem, 0, sizeof pem);
    if (!ok || rename(tmp, path)) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static uint64_t random_serial(void)
{
    uint8_t b[8];
    uint64_t v = 0;
    int i;
    if (vban_sec_random(b, 8))
        return (uint64_t)time(NULL);
    for (i = 0; i < 8; ++i)
        v = (v << 8) | b[i];
    v >>= 1;
    return v ? v : 1;
}

static int load_cert(const char *path, vban_cert_t *c, uint8_t bin[VBAN_CERT_SIZE])
{
    uint8_t tmp[VBAN_CERT_SIZE];
    if (load_pem(path, "VBAN CERT", bin ? bin : tmp, VBAN_CERT_SIZE))
        return -1;
    return vban_cert_decode(bin ? bin : tmp, VBAN_CERT_SIZE, c) ? -1 : 0;
}

/* The CA key, checked against ca.crt by signing a probe. */
static int load_ca(vban_cert_t *ca, uint8_t sk[64])
{
    vban_cert_t probe;
    if (load_cert(pk("ca.crt"), ca, NULL) || !(ca->role & VBAN_CERT_ROLE_CA) || vban_cert_verify(ca, ca->key, 0))
        return -1;
    if (!sk)
        return 0;
    if (load_pem(pk("ca.key"), "VBAN CA KEY", sk, 64))
        return -2;
    probe = *ca;
    if (vban_cert_sign(&probe, sk, ca->key) || vban_cert_verify(&probe, ca->key, 0)) {
        memset(sk, 0, 64);
        return -1;
    }
    return 0;
}

static int issue(const vban_cert_t *ca, const uint8_t ca_sk[64], const char *name, uint8_t role, const uint8_t key[32],
                 long days, vban_cert_t *out, uint8_t bin[VBAN_CERT_SIZE])
{
    uint64_t now = (uint64_t)time(NULL);
    char path[64];
    memset(out, 0, sizeof *out);
    if (strlen(name) > VBAN_CERT_NAME_MAX || !name[0])
        return -1;
    strcpy(out->name, name);
    out->role = role;
    memcpy(out->key, key, 32);
    out->not_before = now - 3600;
    out->not_after = now + (uint64_t)days * 86400u;
    if (out->not_after > ca->not_after)
        out->not_after = ca->not_after;
    out->serial = random_serial();
    if (vban_cert_sign(out, ca_sk, ca->key) || vban_cert_encode(out, bin))
        return -1;
    mkdir(pk("issued"), 0755);
    snprintf(path, sizeof path, "issued/%llu.crt", (unsigned long long)out->serial);
    return save_pem(pk(path), "VBAN CERT", bin, VBAN_CERT_SIZE, 0);
}

static int new_hub(const vban_cert_t *ca, const uint8_t ca_sk[64], const char *name, long days)
{
    uint8_t sk[32], pub[32], bin[VBAN_CERT_SIZE];
    vban_cert_t c;
    if (vban_sec_keygen(sk, pub))
        return -1;
    if (save_pem(pk("hub.key"), "VBAN PRIVATE KEY", sk, 32, 1)) {
        memset(sk, 0, sizeof sk);
        return -1;
    }
    memset(sk, 0, sizeof sk);
    if (issue(ca, ca_sk, name, VBAN_CERT_ROLE_HUB, pub, days, &c, bin))
        return -1;
    unlink(pk("hub.req"));
    return save_pem(pk("hub.crt"), "VBAN CERT", bin, sizeof bin, 0);
}

static void json_str(const char *s)
{
    putchar('"');
    for (; *s; ++s) {
        unsigned char ch = (unsigned char)*s;
        if (ch == '"' || ch == '\\')
            printf("\\%c", ch);
        else if (ch < 0x20 || ch == 0x7F)
            printf("\\u%04x", ch);
        else
            putchar(ch);
    }
    putchar('"');
}

static void fingerprint(const uint8_t key[32], char out[24])
{
    uint8_t id[8];
    int i;
    vban_ca_id(key, id);
    for (i = 0; i < 8; ++i)
        sprintf(out + 2 * i, "%02x", id[i]);
}

/* Whole file, line by line: the list has no size limit. */
static int revoked(uint64_t serial)
{
    char line[64];
    int hit = 0;
    FILE *f = fopen(pk("revoked"), "r");
    while (f && !hit && fgets(line, sizeof line, f))
        hit = strtoull(line, NULL, 10) == serial;
    if (f)
        fclose(f);
    return hit;
}

/* Is this name already on a certificate issued here and not revoked? Routes are bound to
 * certificate names, so two live certificates with one name would share an identity. */
static int name_taken(const char *name)
{
    DIR *d = opendir(pk("issued"));
    struct dirent *e;
    int taken = 0;
    while (d && !taken && (e = readdir(d)) != NULL) {
        char path[300];
        vban_cert_t c;
        if (!strstr(e->d_name, ".crt"))
            continue;
        snprintf(path, sizeof path, "issued/%.250s", e->d_name);
        taken = !load_cert(pk(path), &c, NULL) && !strcmp(c.name, name) && !revoked(c.serial) &&
                (uint64_t)time(NULL) <= c.not_after;
    }
    if (d)
        closedir(d);
    return taken;
}

static void role_json(unsigned r)
{
    printf("[");
    printf("%s%s%s%s", r & VBAN_CERT_ROLE_TX ? "\"tx\"" : "",
           (r & VBAN_CERT_ROLE_TX) && (r & (VBAN_CERT_ROLE_RX | VBAN_CERT_ROLE_HUB)) ? "," : "",
           r & VBAN_CERT_ROLE_RX ? "\"rx\"" : "", (r & VBAN_CERT_ROLE_RX) && (r & VBAN_CERT_ROLE_HUB) ? "," : "");
    printf("%s]", r & VBAN_CERT_ROLE_HUB ? "\"hub\"" : "");
}

static int cmd_status(void)
{
    vban_cert_t ca, hub;
    int have_ca = load_ca(&ca, NULL) == 0, have_hub = load_cert(pk("hub.crt"), &hub, NULL) == 0, first = 1;
    char fp[24];
    DIR *d;
    struct dirent *e;
    uint64_t now = (uint64_t)time(NULL);

    printf("{\"ca\":");
    if (have_ca) {
        fingerprint(ca.key, fp);
        printf("{\"name\":");
        json_str(ca.name);
        printf(",\"not_after\":%llu,\"fingerprint\":\"%s\",\"has_key\":%d}", (unsigned long long)ca.not_after, fp,
               exists(pk("ca.key")));
    } else {
        printf("null");
    }
    printf(",\"hub\":");
    if (have_hub) {
        printf("{\"name\":");
        json_str(hub.name);
        printf(",\"not_after\":%llu,\"valid\":%d}", (unsigned long long)hub.not_after,
               have_ca && !vban_cert_verify(&hub, ca.key, now > 1600000000u ? now : 0));
    } else {
        printf("null");
    }
    printf(",\"hub_request\":%d,\"issued\":[", exists(pk("hub.req")));
    d = opendir(pk("issued"));
    while (d && (e = readdir(d)) != NULL) {
        char path[300];
        vban_cert_t c;
        if (!strstr(e->d_name, ".crt"))
            continue;
        snprintf(path, sizeof path, "issued/%s", e->d_name);
        if (load_cert(pk(path), &c, NULL) || (c.role & (VBAN_CERT_ROLE_HUB | VBAN_CERT_ROLE_CA)))
            continue;
        printf("%s{\"name\":", first ? "" : ",");
        json_str(c.name);
        printf(",\"role\":");
        role_json(c.role);
        printf(",\"serial\":\"%llu\",\"not_after\":%llu,\"revoked\":%d}", (unsigned long long)c.serial,
               (unsigned long long)c.not_after, revoked(c.serial));
        first = 0;
    }
    if (d)
        closedir(d);
    printf("]}\n");
    return 0;
}

static int cmd_init(const char *ca_name, long years, const char *hub_name)
{
    uint8_t sk[64], pub[32], bin[VBAN_CERT_SIZE];
    vban_cert_t ca;
    uint64_t now = (uint64_t)time(NULL);
    if (exists(pk("ca.crt")))
        return fail("a CA already exists (reset it first)");
    if (years < 1 || years > 50)
        return fail("years: 1..50");
    if (now < 1600000000u)
        return fail("the router clock is not set (no NTP yet): certificates would get wrong dates");
    if (vban_ca_keygen(sk, pub) ||
        vban_ca_cert(&ca, ca_name, sk, pub, now - 3600, now + (uint64_t)years * 365u * 86400u, random_serial()) ||
        vban_cert_encode(&ca, bin))
        return fail("bad CA name (1..32 printable characters) or no random source");
    if (save_pem(pk("ca.key"), "VBAN CA KEY", sk, 64, 1) || save_pem(pk("ca.crt"), "VBAN CERT", bin, sizeof bin, 0) ||
        new_hub(&ca, sk, hub_name, years * 365)) {
        memset(sk, 0, sizeof sk);
        return fail("cannot write the PKI files");
    }
    memset(sk, 0, sizeof sk);
    return cmd_status();
}

static int cmd_import(const char *crt, const char *key, const char *hub_name)
{
    uint8_t bin[VBAN_CERT_SIZE], sk[64], hsk[32], hpk[32], req[VBAN_CERT_REQ_SIZE];
    vban_cert_t ca, probe;
    if (exists(pk("ca.crt")))
        return fail("a CA already exists (reset it first)");
    if (load_cert(crt, &ca, bin) || !(ca.role & VBAN_CERT_ROLE_CA) || vban_cert_verify(&ca, ca.key, 0))
        return fail("not a valid VBAN CA certificate");
    if (key) {
        if (load_pem(key, "VBAN CA KEY", sk, 64))
            return fail("not a VBAN CA key");
        probe = ca;
        if (vban_cert_sign(&probe, sk, ca.key) || vban_cert_verify(&probe, ca.key, 0)) {
            memset(sk, 0, sizeof sk);
            return fail("the CA key does not belong to this certificate");
        }
        if (save_pem(pk("ca.key"), "VBAN CA KEY", sk, 64, 1) || save_pem(pk("ca.crt"), "VBAN CERT", bin, sizeof bin, 0) ||
            new_hub(&ca, sk, hub_name, 3650)) {
            memset(sk, 0, sizeof sk);
            return fail("cannot write the PKI files");
        }
        memset(sk, 0, sizeof sk);
        return cmd_status();
    }
    /* CA kept elsewhere: make the hub key and print its request */
    if (save_pem(pk("ca.crt"), "VBAN CERT", bin, sizeof bin, 0) || vban_sec_keygen(hsk, hpk) ||
        save_pem(pk("hub.key"), "VBAN PRIVATE KEY", hsk, 32, 1))
        return fail("cannot write the PKI files");
    memset(hsk, 0, sizeof hsk);
    if (vban_cert_req_encode(hub_name, VBAN_CERT_ROLE_HUB, hpk, req) ||
        save_pem(pk("hub.req"), "VBAN REQUEST", req, sizeof req, 0))
        return fail("bad hub name");
    {
        char txt[1024];
        if (read_text(pk("hub.req"), txt, sizeof txt) > 0)
            fputs(txt, stdout);
    }
    return 0;
}

static int cmd_hub_cert(const char *file)
{
    uint8_t bin[VBAN_CERT_SIZE], sk[32], pub[32];
    vban_cert_t ca, c;
    if (load_ca(&ca, NULL))
        return fail("no CA certificate yet");
    if (load_cert(file, &c, bin) || vban_cert_verify(&c, ca.key, 0) || !(c.role & VBAN_CERT_ROLE_HUB))
        return fail("not a hub certificate from this CA");
    if (load_pem(pk("hub.key"), "VBAN PRIVATE KEY", sk, 32))
        return fail("no hub key (import the CA first)");
    vban_sec_pubkey(sk, pub);
    memset(sk, 0, sizeof sk);
    if (memcmp(pub, c.key, 32))
        return fail("this certificate is for another key (sign the current hub request)");
    if (save_pem(pk("hub.crt"), "VBAN CERT", bin, sizeof bin, 0))
        return fail("cannot write hub.crt");
    unlink(pk("hub.req"));
    return cmd_status();
}

static int cmd_hub_renew(const char *name, long days)
{
    uint8_t sk[64];
    vban_cert_t ca;
    int r = load_ca(&ca, sk);
    if (r)
        return fail(r == -2 ? "the CA key is not on this router" : "no valid CA");
    r = new_hub(&ca, sk, name, days);
    memset(sk, 0, sizeof sk);
    return r ? fail("cannot issue the hub certificate") : cmd_status();
}

static int cmd_sign(const char *file, long days)
{
    uint8_t sk[64], req[VBAN_CERT_REQ_SIZE], key[32], bin[VBAN_CERT_SIZE], role;
    char name[VBAN_CERT_NAME_MAX + 1], txt[1024];
    vban_cert_t ca, c;
    int r = load_ca(&ca, sk);
    if (r)
        return fail(r == -2 ? "the CA key is not on this router: sign with your CA tool" : "no valid CA");
    if (days < 1 || days > 36500 || load_pem(file, "VBAN REQUEST", req, sizeof req) ||
        vban_cert_req_decode(req, sizeof req, name, &role, key)) {
        memset(sk, 0, sizeof sk);
        return fail("not a VBAN certificate request (vban_cert req ...)");
    }
    if (!(role & (VBAN_CERT_ROLE_TX | VBAN_CERT_ROLE_RX)) || (role & (VBAN_CERT_ROLE_CA | VBAN_CERT_ROLE_HUB))) {
        memset(sk, 0, sizeof sk);
        return fail("devices may only ask for tx and/or rx");
    }
    if (name_taken(name)) {
        memset(sk, 0, sizeof sk);
        fprintf(stderr, "a valid certificate named \"%s\" already exists: revoke it first, or use another name\n", name);
        return 1;
    }
    r = issue(&ca, sk, name, role, key, days, &c, bin);
    memset(sk, 0, sizeof sk);
    if (r || vban_pem_encode("VBAN CERT", bin, sizeof bin, txt, sizeof txt) < 0)
        return fail("cannot issue the certificate");
    fputs(txt, stdout);
    return 0;
}

static int cmd_revoke(const char *serial)
{
    char *end;
    unsigned long long v = strtoull(serial, &end, 10);
    FILE *f;
    if (!*serial || *end || !v)
        return fail("serial: a decimal number");
    if (revoked(v))
        return cmd_status();
    f = fopen(pk("revoked"), "a");
    if (!f || fprintf(f, "%llu\n", v) < 0 || fclose(f))
        return fail("cannot write the revocation list");
    return cmd_status();
}

static int cmd_reset(void)
{
    const char *files[] = { "ca.key", "ca.crt", "hub.key", "hub.crt", "hub.req", "revoked" };
    DIR *d;
    struct dirent *e;
    unsigned i;
    for (i = 0; i < sizeof files / sizeof files[0]; ++i)
        unlink(pk(files[i]));
    d = opendir(pk("issued"));
    while (d && (e = readdir(d)) != NULL) {
        char path[300];
        if (e->d_name[0] == '.')
            continue;
        snprintf(path, sizeof path, "issued/%s", e->d_name);
        unlink(pk(path));
    }
    if (d)
        closedir(d);
    rmdir(pk("issued"));
    return cmd_status();
}

int vbanhub_cert_main(int argc, char **argv)
{
    const char *dir = getenv("VBANHUB_PKI");
    const char *c = argc > 1 ? argv[1] : "";
    snprintf(g_dir, sizeof g_dir, "%s", dir && *dir ? dir : "/etc/vbanhub/pki");
    umask(022);
    /* 0755: the unprivileged daemon re-reads certificates and the revocation list; keys are 0600 */
    if (mkdir(g_dir, 0755) && errno != EEXIST)
        return fail("cannot create the PKI directory");
    if (!strcmp(c, "status") && argc == 2) return cmd_status();
    if (!strcmp(c, "init") && argc == 5) return cmd_init(argv[2], atol(argv[3]), argv[4]);
    if (!strcmp(c, "import") && (argc == 4 || argc == 5)) return cmd_import(argv[2], argc == 5 ? argv[3] : NULL, argv[argc - 1]);
    if (!strcmp(c, "hub-cert") && argc == 3) return cmd_hub_cert(argv[2]);
    if (!strcmp(c, "hub-renew") && argc == 4) return cmd_hub_renew(argv[2], atol(argv[3]));
    if (!strcmp(c, "sign") && argc == 4) return cmd_sign(argv[2], atol(argv[3]));
    if (!strcmp(c, "revoke") && argc == 3) return cmd_revoke(argv[2]);
    if (!strcmp(c, "export-ca") && argc == 2) {
        char txt[1024];
        if (read_text(pk("ca.crt"), txt, sizeof txt) < 0)
            return fail("no CA");
        fputs(txt, stdout);
        return 0;
    }
    if (!strcmp(c, "reset") && argc == 2) return cmd_reset();
    fprintf(stderr, "usage: vbanhub cert status | init <ca name> <years> <hub name> | import <ca.crt> [ca.key] <hub name>\n"
                    "       | hub-cert <file> | hub-renew <hub name> <days> | sign <request> <days> | revoke <serial>\n"
                    "       | export-ca | reset\n");
    return 2;
}
