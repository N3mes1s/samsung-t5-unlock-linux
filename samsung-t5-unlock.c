// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <scsi/sg.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define PROGRAM_NAME "samsung-t5-unlock"
#define PROGRAM_VERSION "0.2.0"
#define T5_BUFFER_SIZE 512U
#define T5_PASSWORD_MAX 32U
#define T5_MIN_DATA_SECTORS (1ULL << 21) /* 1 GiB at 512 bytes/sector. */
#define SCSI_TIMEOUT_MS 30000U

static const uint8_t cdb_get_challenge[16] = {
    0x85, 0x08, 0x2e, 0x00, 0xd5, 0x00, 0x01, 0x00,
    0xd7, 0x00, 0x4f, 0x00, 0xc2, 0x00, 0xb0, 0x00,
};

static const uint8_t cdb_submit_response[16] = {
    0x85, 0x0a, 0x26, 0x00, 0xd6, 0x00, 0x01, 0x00,
    0xc6, 0x00, 0x4f, 0x00, 0xc2, 0x00, 0xb0, 0x00,
};

/* Samsung command 4 (d6/c1): update T5 password/security settings. */
static const uint8_t cdb_disable_security[16] = {
    0x85, 0x0a, 0x26, 0x00, 0xd6, 0x00, 0x01, 0x00,
    0xc1, 0x00, 0x4f, 0x00, 0xc2, 0x00, 0xb0, 0x00,
};

static const uint8_t cdb_relink[16] = {
    0x85, 0x0a, 0x26, 0x00, 0xd6, 0x00, 0x01, 0x00,
    0xca, 0x00, 0x4f, 0x00, 0xc2, 0x00, 0xb0, 0x00,
};

struct scsi_result {
    int ioctl_errno;
    unsigned char status;
    unsigned short host_status;
    unsigned short driver_status;
    int resid;
    uint8_t sense[64];
    unsigned char sense_len;
};

struct sha256_context {
    uint32_t state[8];
    uint64_t total_bytes;
    uint8_t block[64];
    size_t block_used;
};

static const uint32_t sha256_constants[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static void secure_clear(void *ptr, size_t len)
{
    volatile uint8_t *p = ptr;
    while (len-- > 0)
        *p++ = 0;
}

static void harden_secret_process(void)
{
    const struct rlimit no_core = {.rlim_cur = 0, .rlim_max = 0};

    (void)setrlimit(RLIMIT_CORE, &no_core);
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

static uint32_t rotate_right(uint32_t value, unsigned int count)
{
    return (value >> count) | (value << (32U - count));
}

static uint32_t load_be32(const uint8_t input[4])
{
    return ((uint32_t)input[0] << 24) |
           ((uint32_t)input[1] << 16) |
           ((uint32_t)input[2] << 8) |
           (uint32_t)input[3];
}

static void store_be32(uint8_t output[4], uint32_t value)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

static void sha256_transform(struct sha256_context *context,
                             const uint8_t block[64])
{
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (size_t i = 0; i < 16; i++)
        words[i] = load_be32(block + i * 4);
    for (size_t i = 16; i < 64; i++) {
        uint32_t s0 = rotate_right(words[i - 15], 7) ^
                      rotate_right(words[i - 15], 18) ^
                      (words[i - 15] >> 3);
        uint32_t s1 = rotate_right(words[i - 2], 17) ^
                      rotate_right(words[i - 2], 19) ^
                      (words[i - 2] >> 10);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }

    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];

    for (size_t i = 0; i < 64; i++) {
        uint32_t sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^
                        rotate_right(e, 25);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + sum1 + choose + sha256_constants[i] + words[i];
        uint32_t sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^
                        rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = sum0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }

    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
    secure_clear(words, sizeof(words));
}

static void sha256_init(struct sha256_context *context)
{
    static const uint32_t initial_state[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };

    memset(context, 0, sizeof(*context));
    memcpy(context->state, initial_state, sizeof(initial_state));
}

static void sha256_update(struct sha256_context *context,
                          const uint8_t *data, size_t data_len)
{
    context->total_bytes += data_len;
    while (data_len > 0) {
        size_t available = sizeof(context->block) - context->block_used;
        size_t take = data_len < available ? data_len : available;

        memcpy(context->block + context->block_used, data, take);
        context->block_used += take;
        data += take;
        data_len -= take;
        if (context->block_used == sizeof(context->block)) {
            sha256_transform(context, context->block);
            context->block_used = 0;
        }
    }
}

static void sha256_final(struct sha256_context *context, uint8_t out[32])
{
    uint64_t bit_length = context->total_bytes * 8U;

    context->block[context->block_used++] = 0x80;
    if (context->block_used > 56) {
        memset(context->block + context->block_used, 0,
               sizeof(context->block) - context->block_used);
        sha256_transform(context, context->block);
        context->block_used = 0;
    }
    memset(context->block + context->block_used, 0, 56 - context->block_used);
    for (size_t i = 0; i < 8; i++)
        context->block[63 - i] = (uint8_t)(bit_length >> (i * 8));
    sha256_transform(context, context->block);

    for (size_t i = 0; i < 8; i++)
        store_be32(out + i * 4, context->state[i]);
    secure_clear(context, sizeof(*context));
}

static void sha256_digest(const uint8_t *data, size_t data_len, uint8_t out[32])
{
    struct sha256_context context;

    sha256_init(&context);
    sha256_update(&context, data, data_len);
    sha256_final(&context, out);
}

static void trim_ascii(char *text)
{
    size_t start = 0;
    size_t len = strlen(text);

    while (start < len && (text[start] == ' ' || text[start] == '\t' ||
                           text[start] == '\r' || text[start] == '\n'))
        start++;
    while (len > start && (text[len - 1] == ' ' || text[len - 1] == '\t' ||
                           text[len - 1] == '\r' || text[len - 1] == '\n'))
        len--;
    if (start > 0)
        memmove(text, text + start, len - start);
    text[len - start] = '\0';
}

static int read_text_file(const char *path, char *out, size_t out_size)
{
    int fd;
    ssize_t got;

    if (out_size == 0)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    got = read(fd, out, out_size - 1);
    close(fd);
    if (got < 0)
        return -1;
    out[got] = '\0';
    trim_ascii(out);
    return 0;
}

static int write_all(int fd, const char *text, size_t length)
{
    size_t written = 0;

    while (written < length) {
        ssize_t result = write(fd, text + written, length - written);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (result == 0)
            return -1;
        written += (size_t)result;
    }
    return 0;
}

static bool is_t5_identity(const char *vendor, const char *model)
{
    return strcmp(vendor, "Samsung") == 0 &&
           strcmp(model, "Portable SSD T5") == 0;
}

static int find_t5_sg(char *out, size_t out_size)
{
    glob_t paths = {0};
    size_t matches = 0;
    int result = -1;

    if (glob("/sys/class/scsi_generic/sg*", 0, NULL, &paths) != 0)
        return -1;

    for (size_t i = 0; i < paths.gl_pathc; i++) {
        char vendor_path[512], model_path[512];
        char vendor[64], model[128];
        const char *name = strrchr(paths.gl_pathv[i], '/');

        if (name == NULL)
            continue;
        name++;
        snprintf(vendor_path, sizeof(vendor_path), "%s/device/vendor",
                 paths.gl_pathv[i]);
        snprintf(model_path, sizeof(model_path), "%s/device/model",
                 paths.gl_pathv[i]);
        if (read_text_file(vendor_path, vendor, sizeof(vendor)) != 0 ||
            read_text_file(model_path, model, sizeof(model)) != 0 ||
            !is_t5_identity(vendor, model))
            continue;
        matches++;
        if (snprintf(out, out_size, "/dev/%s", name) >= (int)out_size) {
            fprintf(stderr, "Device path is too long\n");
            goto done;
        }
    }

    if (matches == 1)
        result = 0;
    else if (matches > 1)
        fprintf(stderr, "More than one Samsung Portable SSD T5 was found; use --device\n");

done:
    globfree(&paths);
    return result;
}

static int sg_command(int fd, const uint8_t *cdb, unsigned int cdb_len,
                      int direction, void *data, unsigned int data_len,
                      struct scsi_result *result)
{
    sg_io_hdr_t io;

    memset(&io, 0, sizeof(io));
    memset(result, 0, sizeof(*result));
    io.interface_id = 'S';
    io.dxfer_direction = direction;
    io.cmd_len = (unsigned char)cdb_len;
    io.mx_sb_len = sizeof(result->sense);
    io.dxfer_len = data_len;
    io.dxferp = data;
    io.cmdp = (unsigned char *)(uintptr_t)cdb;
    io.sbp = result->sense;
    io.timeout = SCSI_TIMEOUT_MS;

    if (ioctl(fd, SG_IO, &io) < 0) {
        result->ioctl_errno = errno;
        return -1;
    }
    result->status = io.status;
    result->host_status = io.host_status;
    result->driver_status = io.driver_status;
    result->resid = io.resid;
    result->sense_len = io.sb_len_wr;
    return 0;
}

static bool scsi_result_ok(const struct scsi_result *result)
{
    return result->ioctl_errno == 0 && result->status == 0 &&
           result->host_status == 0 && result->driver_status == 0;
}

static const uint8_t *ata_return_descriptor(const struct scsi_result *result)
{
    size_t offset = 8;
    size_t sense_end;

    if (result->sense_len < 10 ||
        ((result->sense[0] & 0x7f) != 0x72 &&
         (result->sense[0] & 0x7f) != 0x73))
        return NULL;
    sense_end = 8U + result->sense[7];
    if (sense_end > result->sense_len)
        sense_end = result->sense_len;
    while (offset + 2 <= sense_end) {
        size_t descriptor_size = 2U + result->sense[offset + 1];
        if (descriptor_size < 2 || offset + descriptor_size > sense_end)
            return NULL;
        if (result->sense[offset] == 0x09 && descriptor_size >= 14)
            return result->sense + offset;
        offset += descriptor_size;
    }
    return NULL;
}

static bool ata_result_ok(const struct scsi_result *result)
{
    const uint8_t *descriptor;
    uint8_t ata_status;

    if (result->ioctl_errno != 0 || result->host_status != 0)
        return false;
    if (result->status == 0 && result->driver_status == 0)
        return true;

    /*
     * The T5 CDBs set ATA PASS-THROUGH CK_COND. Linux therefore reports
     * CHECK CONDITION plus an ATA Return Descriptor even when ATA completed
     * successfully. ATA status bits ERR (0) and DF (5) identify a real error.
     */
    if ((result->status & 0x7e) != 0x02 ||
        ((result->driver_status & 0x0f) != 0x00 &&
         (result->driver_status & 0x0f) != 0x08))
        return false;
    descriptor = ata_return_descriptor(result);
    if (descriptor == NULL)
        return false;
    ata_status = descriptor[13];
    return (ata_status & 0x21) == 0;
}

static void print_scsi_error(const char *operation, const struct scsi_result *result)
{
    unsigned int key = 0, asc = 0, ascq = 0;
    const uint8_t *ata_descriptor;

    if (result->ioctl_errno != 0) {
        fprintf(stderr, "%s: SG_IO failed: %s\n", operation,
                strerror(result->ioctl_errno));
        return;
    }
    if (result->sense_len >= 14 &&
        ((result->sense[0] & 0x7f) == 0x70 ||
         (result->sense[0] & 0x7f) == 0x71)) {
        key = result->sense[2] & 0x0f;
        asc = result->sense[12];
        ascq = result->sense[13];
    } else if (result->sense_len >= 4 &&
               ((result->sense[0] & 0x7f) == 0x72 ||
                (result->sense[0] & 0x7f) == 0x73)) {
        key = result->sense[1] & 0x0f;
        asc = result->sense[2];
        ascq = result->sense[3];
    }
    fprintf(stderr,
            "%s: SCSI status=0x%02x host=0x%02x driver=0x%02x "
            "sense=%x/%02x/%02x\n",
            operation, result->status, result->host_status,
            result->driver_status, key, asc, ascq);
    ata_descriptor = ata_return_descriptor(result);
    if (ata_descriptor != NULL)
        fprintf(stderr, "%s: ATA status=0x%02x error=0x%02x\n",
                operation, ata_descriptor[13], ata_descriptor[3]);
}

static int inquiry_t5(int fd)
{
    const uint8_t cdb[6] = {0x12, 0x00, 0x00, 0x00, 96, 0x00};
    uint8_t data[96] = {0};
    struct scsi_result result;
    char vendor[9] = {0}, model[17] = {0};
    int rc;

    rc = sg_command(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV,
                    data, sizeof(data), &result);
    if (rc != 0 || !scsi_result_ok(&result)) {
        print_scsi_error("INQUIRY", &result);
        return -1;
    }
    if ((int)sizeof(data) - result.resid < 32) {
        fprintf(stderr, "INQUIRY returned too little data\n");
        return -1;
    }
    memcpy(vendor, data + 8, 8);
    memcpy(model, data + 16, 16);
    trim_ascii(vendor);
    trim_ascii(model);
    if (!is_t5_identity(vendor, model)) {
        fprintf(stderr, "Refusing device: INQUIRY says vendor='%s' model='%s'\n",
                vendor, model);
        return -1;
    }
    printf("Verified device: %s %s\n", vendor, model);
    return 0;
}

static int derive_response(const uint8_t *password, size_t password_len,
                           const uint8_t challenge[T5_BUFFER_SIZE],
                           uint8_t response[32])
{
    uint8_t work[64] = {0};
    int rc = -1;

    if (password_len == 0 || password_len > T5_PASSWORD_MAX)
        return -1;

    memcpy(work, password, password_len);
    memcpy(work + 0x20, challenge + 0x30, 0x10);
    sha256_digest(work, 0x30, work);

    memcpy(work + 0x20, challenge, 0x20);
    sha256_digest(work, sizeof(work), response);
    rc = 0;

    secure_clear(work, sizeof(work));
    return rc;
}

static int prompt_password(uint8_t password[T5_PASSWORD_MAX + 1], size_t *length)
{
    char input[256];
    struct termios old_term, no_echo;
    sigset_t blocked, previous;
    int tty_fd = -1;
    bool term_changed = false, signals_blocked = false, input_locked = false;
    ssize_t got;
    int rc = -1;

    if (mlock(input, sizeof(input)) == 0)
        input_locked = true;
    tty_fd = open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (tty_fd < 0) {
        fprintf(stderr, "A controlling terminal is required for the hidden password prompt\n");
        goto done;
    }

    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous) == 0)
        signals_blocked = true;

    if (tcgetattr(tty_fd, &old_term) != 0)
        goto done;
    no_echo = old_term;
    no_echo.c_lflag &= ~(ECHO);
    if (tcsetattr(tty_fd, TCSAFLUSH, &no_echo) != 0)
        goto done;
    term_changed = true;

    if (write_all(tty_fd, "T5 password: ", 13) != 0)
        goto done;
    got = read(tty_fd, input, sizeof(input) - 1);
    if (got <= 0)
        goto done;
    input[got] = '\0';
    (void)write_all(tty_fd, "\n", 1);

    input[strcspn(input, "\r\n")] = '\0';
    *length = strlen(input);
    if (*length == 0 || *length > T5_PASSWORD_MAX) {
        fprintf(stderr, "Password must contain 1 to %u bytes\n", T5_PASSWORD_MAX);
        goto done;
    }
    memcpy(password, input, *length);
    password[*length] = '\0';
    rc = 0;

done:
    secure_clear(input, sizeof(input));
    if (term_changed)
        tcsetattr(tty_fd, TCSAFLUSH, &old_term);
    if (signals_blocked)
        sigprocmask(SIG_SETMASK, &previous, NULL);
    if (tty_fd >= 0)
        close(tty_fd);
    if (input_locked)
        munlock(input, sizeof(input));
    return rc;
}

static int request_challenge(int fd, uint8_t challenge[T5_BUFFER_SIZE])
{
    struct scsi_result result;
    int rc;

    memset(challenge, 0, T5_BUFFER_SIZE);
    rc = sg_command(fd, cdb_get_challenge, sizeof(cdb_get_challenge),
                    SG_DXFER_FROM_DEV, challenge, T5_BUFFER_SIZE, &result);
    if (rc != 0 || !ata_result_ok(&result)) {
        print_scsi_error("challenge request", &result);
        return -1;
    }
    if ((int)T5_BUFFER_SIZE - result.resid < 64) {
        fprintf(stderr, "Challenge request returned too little data\n");
        return -1;
    }
    return 0;
}

static int send_response(int fd, const uint8_t response[32])
{
    uint8_t payload[T5_BUFFER_SIZE] = {0};
    struct scsi_result result;
    int rc;

    memcpy(payload + 0x20, response, 32);
    rc = sg_command(fd, cdb_submit_response, sizeof(cdb_submit_response),
                    SG_DXFER_TO_DEV, payload, sizeof(payload), &result);
    secure_clear(payload, sizeof(payload));
    if (rc != 0 || !ata_result_ok(&result)) {
        print_scsi_error("authentication", &result);
        fprintf(stderr, "The T5 rejected the response (usually a wrong password)\n");
        return -1;
    }
    return 0;
}

static int disable_security(int fd, const uint8_t response[32])
{
    uint8_t payload[T5_BUFFER_SIZE] = {0};
    struct scsi_result result;
    int rc;

    /* Samsung PSSD_DeleteUserPassword: operation 6, hash at offset 0x10. */
    payload[0] = 0x06;
    memcpy(payload + 0x10, response, 32);
    rc = sg_command(fd, cdb_disable_security, sizeof(cdb_disable_security),
                    SG_DXFER_TO_DEV, payload, sizeof(payload), &result);
    secure_clear(payload, sizeof(payload));
    if (rc != 0 || !ata_result_ok(&result)) {
        print_scsi_error("disable security", &result);
        fprintf(stderr,
                "The T5 rejected the security change (usually a wrong password)\n");
        return -1;
    }
    return 0;
}

static int send_relink(int fd)
{
    uint8_t payload[T5_BUFFER_SIZE] = {0};
    struct scsi_result result;
    int rc;

    rc = sg_command(fd, cdb_relink, sizeof(cdb_relink), SG_DXFER_TO_DEV,
                    payload, sizeof(payload), &result);
    secure_clear(payload, sizeof(payload));
    if (rc != 0 || !ata_result_ok(&result)) {
        /* A successful relink can remove the old device during SG_IO. */
        if (result.ioctl_errno == ENODEV || result.host_status != 0) {
            fprintf(stderr, "Device disconnected during relink; checking its new state\n");
            return 0;
        }
        print_scsi_error("relink", &result);
        return -1;
    }
    return 0;
}

static int find_unlocked_block(char *out, size_t out_size, uint64_t *bytes)
{
    glob_t paths = {0};
    int rc = -1;

    if (glob("/sys/class/block/sd*", 0, NULL, &paths) != 0)
        return -1;
    for (size_t i = 0; i < paths.gl_pathc; i++) {
        char check_path[512], vendor_path[512], model_path[512], size_path[512];
        char vendor[64], model[128], size_text[64];
        const char *name;
        unsigned long long sectors;

        snprintf(check_path, sizeof(check_path), "%s/partition", paths.gl_pathv[i]);
        if (access(check_path, F_OK) == 0)
            continue;
        snprintf(vendor_path, sizeof(vendor_path), "%s/device/vendor", paths.gl_pathv[i]);
        snprintf(model_path, sizeof(model_path), "%s/device/model", paths.gl_pathv[i]);
        snprintf(size_path, sizeof(size_path), "%s/size", paths.gl_pathv[i]);
        if (read_text_file(vendor_path, vendor, sizeof(vendor)) != 0 ||
            read_text_file(model_path, model, sizeof(model)) != 0 ||
            read_text_file(size_path, size_text, sizeof(size_text)) != 0 ||
            !is_t5_identity(vendor, model))
            continue;
        errno = 0;
        sectors = strtoull(size_text, NULL, 10);
        if (errno != 0 || sectors <= T5_MIN_DATA_SECTORS)
            continue;
        name = strrchr(paths.gl_pathv[i], '/');
        if (name == NULL)
            continue;
        name++;
        if (snprintf(out, out_size, "/dev/%s", name) >= (int)out_size)
            continue;
        *bytes = sectors * 512ULL;
        rc = 0;
        break;
    }
    globfree(&paths);
    return rc;
}

static int wait_for_unlocked_block(char *out, size_t out_size, uint64_t *bytes)
{
    const struct timespec delay = {.tv_sec = 0, .tv_nsec = 250000000};

    for (unsigned int attempt = 0; attempt < 80; attempt++) {
        if (find_unlocked_block(out, out_size, bytes) == 0)
            return 0;
        nanosleep(&delay, NULL);
    }
    return -1;
}

static int self_test(void)
{
    static const uint8_t abc_digest[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    static const uint8_t response_expected[32] = {
        0x94, 0x8f, 0xaf, 0x6b, 0x3f, 0x31, 0xdc, 0xb3,
        0x9b, 0xe0, 0x24, 0xfb, 0x47, 0x64, 0x23, 0xc8,
        0x72, 0x84, 0x45, 0x64, 0xb3, 0x84, 0x96, 0x13,
        0x19, 0xe0, 0x6b, 0x23, 0xd1, 0x17, 0xa5, 0x31,
    };
    const uint8_t password[] = "test-password";
    uint8_t digest[32], response[32], challenge[T5_BUFFER_SIZE];
    struct scsi_result ata_result;

    for (size_t i = 0; i < sizeof(challenge); i++)
        challenge[i] = (uint8_t)i;
    sha256_digest((const uint8_t *)"abc", 3, digest);
    if (memcmp(digest, abc_digest, sizeof(digest)) != 0) {
        fprintf(stderr, "SHA-256 self-test failed\n");
        return 1;
    }
    if (derive_response(password, sizeof(password) - 1, challenge, response) != 0 ||
        memcmp(response, response_expected, sizeof(response)) != 0) {
        fprintf(stderr, "T5 response derivation self-test failed\n");
        return 1;
    }
    memset(&ata_result, 0, sizeof(ata_result));
    ata_result.status = 0x02;
    ata_result.driver_status = 0x08;
    ata_result.sense_len = 22;
    ata_result.sense[0] = 0x72;
    ata_result.sense[1] = 0x01;
    ata_result.sense[2] = 0x00;
    ata_result.sense[3] = 0x1d;
    ata_result.sense[7] = 14;
    ata_result.sense[8] = 0x09;
    ata_result.sense[9] = 0x0c;
    ata_result.sense[21] = 0x50;
    if (!ata_result_ok(&ata_result)) {
        fprintf(stderr, "ATA success descriptor self-test failed\n");
        return 1;
    }
    ata_result.sense[11] = 0x04;
    ata_result.sense[21] = 0x51;
    if (ata_result_ok(&ata_result)) {
        fprintf(stderr, "ATA error descriptor self-test failed\n");
        return 1;
    }
    secure_clear(digest, sizeof(digest));
    secure_clear(response, sizeof(response));
    secure_clear(challenge, sizeof(challenge));
    puts("Self-test passed");
    return 0;
}

static void usage(FILE *stream)
{
    fprintf(stream,
            "Usage: %s [--device /dev/sgN] "
            "[--probe | --challenge-only | --disable-security]\n"
            "       %s --self-test\n\n"
            "Manage password protection on a Samsung Portable SSD T5 from Linux.\n"
            "With no mode option, the password is read from a hidden terminal prompt.\n\n"
            "  --device PATH     use this SCSI generic device instead of auto-detecting\n"
            "  --probe           verify device identity only (no proprietary commands)\n"
            "  --challenge-only  verify the read-only challenge command, print no bytes\n"
            "  --disable-security permanently turn off password locking (preserves data)\n"
            "  --self-test       test SHA-256 and response derivation without a device\n"
            "  --help            show this help\n"
            "  --version         show version\n",
            PROGRAM_NAME, PROGRAM_NAME);
}

int main(int argc, char **argv)
{
    enum {
        MODE_UNLOCK,
        MODE_PROBE,
        MODE_CHALLENGE,
        MODE_DISABLE_SECURITY,
        MODE_SELF_TEST
    } mode = MODE_UNLOCK;
    char device[256] = {0};
    uint8_t challenge[T5_BUFFER_SIZE] = {0};
    uint8_t response[32] = {0};
    uint8_t password[T5_PASSWORD_MAX + 1] = {0};
    size_t password_len = 0;
    int fd = -1, exit_code = 1;
    bool password_locked = false, mode_selected = false;

    harden_secret_process();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            if (device[0] != '\0') {
                fprintf(stderr, "--device may only be specified once\n");
                goto done;
            }
            if (snprintf(device, sizeof(device), "%s", argv[++i]) >= (int)sizeof(device)) {
                fprintf(stderr, "Device path is too long\n");
                goto done;
            }
        } else if (strcmp(argv[i], "--probe") == 0) {
            if (mode_selected) {
                fprintf(stderr, "Operation options are mutually exclusive\n");
                goto done;
            }
            mode_selected = true;
            mode = MODE_PROBE;
        } else if (strcmp(argv[i], "--challenge-only") == 0) {
            if (mode_selected) {
                fprintf(stderr, "Operation options are mutually exclusive\n");
                goto done;
            }
            mode_selected = true;
            mode = MODE_CHALLENGE;
        } else if (strcmp(argv[i], "--disable-security") == 0) {
            if (mode_selected) {
                fprintf(stderr, "Operation options are mutually exclusive\n");
                goto done;
            }
            mode_selected = true;
            mode = MODE_DISABLE_SECURITY;
        } else if (strcmp(argv[i], "--self-test") == 0) {
            if (mode_selected) {
                fprintf(stderr, "Operation options are mutually exclusive\n");
                goto done;
            }
            mode_selected = true;
            mode = MODE_SELF_TEST;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("%s %s\n", PROGRAM_NAME, PROGRAM_VERSION);
            return 0;
        } else {
            fprintf(stderr, "Unknown or incomplete option: %s\n", argv[i]);
            usage(stderr);
            goto done;
        }
    }

    if (mode == MODE_SELF_TEST)
        return self_test();

    if (device[0] == '\0' && find_t5_sg(device, sizeof(device)) != 0) {
        fprintf(stderr, "No Samsung Portable SSD T5 SCSI generic device found\n");
        fprintf(stderr, "Ensure it is connected and its kernel mass-storage driver is bound\n");
        goto done;
    }
    printf("Opening %s\n", device);
    fd = open(device, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "Cannot open %s: %s\n", device, strerror(errno));
        goto done;
    }
    if (inquiry_t5(fd) != 0)
        goto done;
    if (mode == MODE_PROBE) {
        puts("Probe passed; no proprietary command was sent");
        exit_code = 0;
        goto done;
    }

    if (request_challenge(fd, challenge) != 0)
        goto done;
    puts("T5 challenge command succeeded");
    if (mode == MODE_CHALLENGE) {
        exit_code = 0;
        goto done;
    }

    if (mlock(password, sizeof(password)) == 0)
        password_locked = true;
    if (prompt_password(password, &password_len) != 0)
        goto done;
    if (derive_response(password, password_len, challenge, response) != 0) {
        fprintf(stderr, "Could not derive the T5 authentication response\n");
        goto done;
    }
    secure_clear(password, sizeof(password));
    password_len = 0;

    if (mode == MODE_DISABLE_SECURITY) {
        if (disable_security(fd, response) != 0)
            goto done;
        secure_clear(response, sizeof(response));
        puts("Security mode disabled; password locking has been removed");
        exit_code = 0;
        goto done;
    }

    if (send_response(fd, response) != 0)
        goto done;
    secure_clear(response, sizeof(response));
    puts("Password accepted; requesting full-capacity relink");
    if (send_relink(fd) != 0)
        goto done;
    close(fd);
    fd = -1;

    {
        char block_device[256];
        uint64_t bytes = 0;
        if (wait_for_unlocked_block(block_device, sizeof(block_device), &bytes) == 0) {
            printf("Unlocked: %s (%llu bytes)\n", block_device,
                   (unsigned long long)bytes);
            exit_code = 0;
        } else {
            fprintf(stderr,
                    "Authentication and relink completed, but the full-capacity block "
                    "device did not appear within 20 seconds\n");
            exit_code = 2;
        }
    }

done:
    if (fd >= 0)
        close(fd);
    secure_clear(password, sizeof(password));
    secure_clear(response, sizeof(response));
    secure_clear(challenge, sizeof(challenge));
    if (password_locked)
        munlock(password, sizeof(password));
    return exit_code;
}
