#define _GNU_SOURCE

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/if.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#define NONCE_LEN 12
#define TAG_LEN 16
#define TRAILER_LEN (NONCE_LEN + TAG_LEN)
#define MAX_FRAME 65536

static unsigned char session_key[32];
static uint32_t nonce_prefix;
static uint64_t nonce_counter;

static void die(const char *message)
{
    perror(message);
    exit(EXIT_FAILURE);
}

static int read_all(int fd, void *buffer, size_t length)
{
    unsigned char *cursor = buffer;

    while (length > 0) {
        ssize_t bytes_read = read(fd, cursor, length);
        if (bytes_read <= 0) {
            return -1;
        }

        cursor += bytes_read;
        length -= (size_t)bytes_read;
    }

    return 0;
}

static int write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;

    while (length > 0) {
        ssize_t bytes_written = write(fd, cursor, length);
        if (bytes_written <= 0) {
            return -1;
        }

        cursor += bytes_written;
        length -= (size_t)bytes_written;
    }

    return 0;
}

static void establish_session(int control_fd, int is_client,
                              const unsigned char psk[32])
{
    EVP_PKEY_CTX *keygen_context = NULL;
    EVP_PKEY_CTX *derive_context = NULL;
    EVP_PKEY_CTX *hkdf_context = NULL;
    EVP_PKEY *local_key = NULL;
    EVP_PKEY *peer_key = NULL;

    unsigned char public_key[32];
    unsigned char peer_public_key[32];
    unsigned char proof[32];
    unsigned char expected_proof[32];
    unsigned char transcript[64];
    unsigned char shared_secret[32];
    size_t public_key_length = sizeof(public_key);
    size_t secret_length = sizeof(shared_secret);
    unsigned int proof_length = sizeof(proof);

    keygen_context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (keygen_context == NULL ||
        EVP_PKEY_keygen_init(keygen_context) <= 0 ||
        EVP_PKEY_keygen(keygen_context, &local_key) <= 0 ||
        EVP_PKEY_get_raw_public_key(local_key, public_key,
                                    &public_key_length) <= 0) {
        die("X25519 key generation");
    }

    if (is_client) {
        unsigned char labeled_transcript[70];

        if (write_all(control_fd, public_key, sizeof(public_key)) != 0 ||
            read_all(control_fd, peer_public_key,
                     sizeof(peer_public_key)) != 0 ||
            read_all(control_fd, proof, sizeof(proof)) != 0) {
            die("client handshake I/O");
        }

        memcpy(transcript, public_key, sizeof(public_key));
        memcpy(transcript + sizeof(public_key), peer_public_key,
               sizeof(peer_public_key));
        memcpy(labeled_transcript, transcript, sizeof(transcript));
        memcpy(labeled_transcript + sizeof(transcript), "server", 6);

        HMAC(EVP_sha256(), psk, 32, labeled_transcript,
             sizeof(labeled_transcript), expected_proof, &proof_length);
        if (CRYPTO_memcmp(proof, expected_proof, sizeof(proof)) != 0) {
            fprintf(stderr, "server authentication failed\n");
            exit(EXIT_FAILURE);
        }

        memcpy(labeled_transcript + sizeof(transcript), "client", 6);
        HMAC(EVP_sha256(), psk, 32, labeled_transcript,
             sizeof(labeled_transcript), proof, &proof_length);
        if (write_all(control_fd, proof, sizeof(proof)) != 0) {
            die("sending client handshake proof");
        }
    } else {
        unsigned char labeled_transcript[70];

        if (read_all(control_fd, peer_public_key,
                     sizeof(peer_public_key)) != 0) {
            die("receiving client public key");
        }

        memcpy(transcript, peer_public_key, sizeof(peer_public_key));
        memcpy(transcript + sizeof(peer_public_key), public_key,
               sizeof(public_key));
        memcpy(labeled_transcript, transcript, sizeof(transcript));
        memcpy(labeled_transcript + sizeof(transcript), "server", 6);

        HMAC(EVP_sha256(), psk, 32, labeled_transcript,
             sizeof(labeled_transcript), proof, &proof_length);
        if (write_all(control_fd, public_key, sizeof(public_key)) != 0 ||
            write_all(control_fd, proof, sizeof(proof)) != 0) {
            die("sending server handshake proof");
        }

        if (read_all(control_fd, proof, sizeof(proof)) != 0) {
            die("receiving client handshake proof");
        }

        memcpy(labeled_transcript + sizeof(transcript), "client", 6);
        HMAC(EVP_sha256(), psk, 32, labeled_transcript,
             sizeof(labeled_transcript), expected_proof, &proof_length);
        if (CRYPTO_memcmp(proof, expected_proof, sizeof(proof)) != 0) {
            fprintf(stderr, "peer authentication failed\n");
            exit(EXIT_FAILURE);
        }
    }

    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                           peer_public_key,
                                           sizeof(peer_public_key));
    derive_context = EVP_PKEY_CTX_new(local_key, NULL);
    if (peer_key == NULL || derive_context == NULL ||
        EVP_PKEY_derive_init(derive_context) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_context, peer_key) <= 0 ||
        EVP_PKEY_derive(derive_context, shared_secret, &secret_length) <= 0) {
        die("X25519 shared-secret derivation");
    }

    size_t session_key_length = sizeof(session_key);
    hkdf_context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (hkdf_context == NULL ||
        EVP_PKEY_derive_init(hkdf_context) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(hkdf_context, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(hkdf_context, transcript,
                                    sizeof(transcript)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(hkdf_context, shared_secret,
                                   sizeof(shared_secret)) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            hkdf_context, (const unsigned char *)"inline-tcp-v1", 13) <= 0 ||
        EVP_PKEY_derive(hkdf_context, session_key,
                        &session_key_length) <= 0) {
        die("HKDF session-key derivation");
    }

    nonce_prefix = htonl(is_client ? 0x44314331u : 0x44324332u);
    nonce_counter = 0;

    EVP_PKEY_CTX_free(hkdf_context);
    EVP_PKEY_CTX_free(derive_context);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(local_key);
    EVP_PKEY_CTX_free(keygen_context);
}

static int aes_gcm_crypt(int encrypt, const unsigned char *input,
                         int input_length, const unsigned char nonce[12],
                         const unsigned char *input_tag,
                         unsigned char *output, unsigned char *output_tag,
                         const unsigned char *aad, int aad_length)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    int bytes_processed = 0;
    int output_length = 0;
    int ok;

    if (context == NULL) {
        return -1;
    }

    if (encrypt) {
        ok = EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL,
                                NULL) > 0 &&
             EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, 12,
                                 NULL) > 0 &&
             EVP_EncryptInit_ex(context, NULL, NULL, session_key, nonce) > 0 &&
             EVP_EncryptUpdate(context, NULL, &bytes_processed,
                               aad, aad_length) > 0 &&
             EVP_EncryptUpdate(context, output, &bytes_processed,
                               input, input_length) > 0;

        output_length = bytes_processed;
        ok = ok && EVP_EncryptFinal_ex(context, output + output_length,
                                       &bytes_processed) > 0;
        output_length += bytes_processed;
        ok = ok && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
                                       TAG_LEN, output_tag) > 0;
    } else {
        ok = EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL,
                                NULL) > 0 &&
             EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, 12,
                                 NULL) > 0 &&
             EVP_DecryptInit_ex(context, NULL, NULL, session_key, nonce) > 0 &&
             EVP_DecryptUpdate(context, NULL, &bytes_processed,
                               aad, aad_length) > 0 &&
             EVP_DecryptUpdate(context, output, &bytes_processed,
                               input, input_length) > 0;

        output_length = bytes_processed;
        ok = ok && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG,
                                       TAG_LEN, (void *)input_tag) > 0 &&
             EVP_DecryptFinal_ex(context, output + output_length,
                                 &bytes_processed) > 0;
        output_length += bytes_processed;
    }

    EVP_CIPHER_CTX_free(context);
    return ok ? output_length : -1;
}

static uint16_t ipv4_checksum(const unsigned char *data, size_t length)
{
    uint32_t sum = 0;

    while (length > 1) {
        sum += (uint16_t)((data[0] << 8) | data[1]);
        data += 2;
        length -= 2;
    }

    if (length > 0) {
        sum += (uint16_t)(data[0] << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

static uint16_t tcp_checksum(const unsigned char *ip_header,
                             const unsigned char *tcp_segment,
                             size_t tcp_length)
{
    uint32_t sum = 0;
    const unsigned char *addresses = ip_header + 12;

    for (int i = 0; i < 8; i += 2) {
        sum += (addresses[i] << 8) | addresses[i + 1];
    }

    sum += IPPROTO_TCP;
    sum += (uint16_t)tcp_length;

    for (size_t i = 0; i + 1 < tcp_length; i += 2) {
        sum += (tcp_segment[i] << 8) | tcp_segment[i + 1];
    }

    if (tcp_length & 1) {
        sum += tcp_segment[tcp_length - 1] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

static int transform_packet(unsigned char *frame, size_t *frame_length,
                            int decrypt, uint16_t selected_port)
{
    if (*frame_length < ETH_HLEN + 20 ||
        ntohs(*(uint16_t *)(frame + 12)) != ETH_P_IP) {
        return 0;
    }

    unsigned char *ip = frame + ETH_HLEN;
    uint16_t fragment_info = ntohs(*(uint16_t *)(ip + 6));
    if ((ip[0] >> 4) != 4 || ip[9] != IPPROTO_TCP ||
        (fragment_info & 0x3fff) != 0) {
        return 0;
    }

    size_t ip_header_length = (ip[0] & 0x0f) * 4;
    size_t ip_total_length = ntohs(*(uint16_t *)(ip + 2));
    if (ip_header_length < 20 ||
        ip_total_length < ip_header_length + 20 ||
        *frame_length < ETH_HLEN + ip_total_length) {
        return -1;
    }

    unsigned char *tcp = ip + ip_header_length;
    size_t tcp_header_length = (tcp[12] >> 4) * 4;
    if (tcp_header_length < 20 ||
        ip_total_length < ip_header_length + tcp_header_length) {
        return -1;
    }

    uint16_t source_port = ntohs(*(uint16_t *)tcp);
    uint16_t destination_port = ntohs(*(uint16_t *)(tcp + 2));
    if (source_port != selected_port && destination_port != selected_port) {
        return 0;
    }

    size_t payload_length = ip_total_length - ip_header_length - tcp_header_length;
    unsigned char *payload = tcp + tcp_header_length;
    unsigned char *temporary = malloc(payload_length + TRAILER_LEN + 1);
    if (temporary == NULL) {
        return -1;
    }

    size_t aad_length = 8 + tcp_header_length;
    unsigned char *aad = malloc(aad_length);
    if (aad == NULL) {
        free(temporary);
        return -1;
    }

    memcpy(aad, ip + 12, 8);
    memcpy(aad + 8, tcp, tcp_header_length);
    aad[8 + 16] = 0;
    aad[8 + 17] = 0;

    if (!decrypt) {
        if (ip_total_length + TRAILER_LEN > 65535 ||
            payload_length == 0 || nonce_counter == UINT64_MAX) {
            free(aad);
            free(temporary);
            return 0;
        }

        unsigned char nonce[NONCE_LEN];
        unsigned char tag[TAG_LEN];
        memcpy(nonce, &nonce_prefix, sizeof(nonce_prefix));

        uint64_t counter_network_order = htobe64(nonce_counter++);
        memcpy(nonce + sizeof(nonce_prefix), &counter_network_order,
               sizeof(counter_network_order));

        int encrypted_length = aes_gcm_crypt(
            1, payload, (int)payload_length, nonce, NULL, temporary, tag,
            aad, (int)aad_length);
        if (encrypted_length < 0) {
            free(aad);
            free(temporary);
            return -1;
        }

        memcpy(payload, temporary, (size_t)encrypted_length);
        memcpy(payload + encrypted_length, nonce, sizeof(nonce));
        memcpy(payload + encrypted_length + sizeof(nonce), tag, sizeof(tag));
        ip_total_length += (size_t)encrypted_length + TRAILER_LEN - payload_length;
    } else {
        if (payload_length == 0) {
            free(aad);
            free(temporary);
            return 0;
        }

        if (payload_length < TRAILER_LEN) {
            free(aad);
            free(temporary);
            return -1;
        }

        size_t ciphertext_length = payload_length - TRAILER_LEN;
        unsigned char *nonce = payload + ciphertext_length;
        unsigned char *tag = nonce + NONCE_LEN;

        int decrypted_length = aes_gcm_crypt(
            0, payload, (int)ciphertext_length, nonce, tag, temporary, NULL,
            aad, (int)aad_length);
        if (decrypted_length < 0) {
            free(aad);
            free(temporary);
            return -1;
        }

        memcpy(payload, temporary, (size_t)decrypted_length);
        ip_total_length -= TRAILER_LEN;
    }

    *(uint16_t *)(ip + 2) = htons((uint16_t)ip_total_length);
    ip[10] = 0;
    ip[11] = 0;
    *(uint16_t *)(ip + 10) = htons(ipv4_checksum(ip, ip_header_length));

    tcp[16] = 0;
    tcp[17] = 0;
    size_t tcp_length = ip_total_length - ip_header_length;
    *(uint16_t *)(tcp + 16) = htons(tcp_checksum(ip, tcp, tcp_length));

    *frame_length = ETH_HLEN + ip_total_length;
    free(aad);
    free(temporary);
    return 1;
}

static int open_packet_socket(const char *interface_name)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        die("AF_PACKET socket");
    }

    struct sockaddr_ll address = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = (int)if_nametoindex(interface_name),
    };

    if (address.sll_ifindex == 0 ||
        bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        die("AF_PACKET bind");
    }

    return fd;
}

static void send_frame(int fd, const char *interface_name,
                       const unsigned char *frame, size_t frame_length)
{
    struct sockaddr_ll address = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = (int)if_nametoindex(interface_name),
        .sll_halen = ETH_ALEN,
    };

    memcpy(address.sll_addr, frame, ETH_ALEN);
    if (sendto(fd, frame, frame_length, 0,
               (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("sendto");
    }
}

static int parse_mac(const char *text, unsigned char mac[6])
{
    return sscanf(text, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

static int parse_key(const char *text, unsigned char key[32])
{
    if (strlen(text) != 64) {
        return 0;
    }

    for (int i = 0; i < 32; i++) {
        unsigned int value;
        if (sscanf(text + 2 * i, "%2x", &value) != 1) {
            return 0;
        }
        key[i] = (unsigned char)value;
    }

    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 10) {
        fprintf(stderr,
                "Usage: %s listen|connect control-ip control-port psk-hex "
                "host-if peer-if peer-mac tcp-port host-mac\n",
                argv[0]);
        return 2;
    }

    int is_client = strcmp(argv[1], "connect") == 0;
    if (!is_client && strcmp(argv[1], "listen") != 0) {
        return 2;
    }

    unsigned char psk[32];
    unsigned char peer_mac[6];
    unsigned char host_mac[6];
    if (!parse_key(argv[4], psk) || !parse_mac(argv[7], peer_mac)) {
        fprintf(stderr, "invalid PSK or peer MAC\n");
        return 2;
    }
    if (!parse_mac(argv[9], host_mac)) {
        fprintf(stderr, "invalid host MAC\n");
        return 2;
    }

    char *end;
    long control_port = strtol(argv[3], &end, 10);
    long selected_port = strtol(argv[8], &end, 10);
    if (control_port < 1 || control_port > 65535 ||
        selected_port < 1 || selected_port > 65535) {
        fprintf(stderr, "invalid TCP port\n");
        return 2;
    }

    int control_fd;
    if (is_client) {
        control_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in server_address = {
            .sin_family = AF_INET,
            .sin_port = htons((uint16_t)control_port),
        };

        if (inet_pton(AF_INET, argv[2], &server_address.sin_addr) != 1 ||
            connect(control_fd, (struct sockaddr *)&server_address,
                    sizeof(server_address)) < 0) {
            die("control connect");
        }
    } else {
        int listener_fd = socket(AF_INET, SOCK_STREAM, 0);
        int reuse_address = 1;
        setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR,
                   &reuse_address, sizeof(reuse_address));

        struct sockaddr_in listen_address = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = INADDR_ANY,
            .sin_port = htons((uint16_t)control_port),
        };

        if (bind(listener_fd, (struct sockaddr *)&listen_address,
                 sizeof(listen_address)) < 0 ||
            listen(listener_fd, 1) < 0) {
            die("control listen");
        }

        control_fd = accept(listener_fd, NULL, NULL);
        if (control_fd < 0) {
            die("control accept");
        }
        close(listener_fd);
    }

    establish_session(control_fd, is_client, psk);
    close(control_fd);
    fprintf(stderr, "authenticated session established\n");

    int host_fd = open_packet_socket(argv[5]);
    int peer_fd = open_packet_socket(argv[6]);
    unsigned char *frame = malloc(MAX_FRAME);
    if (frame == NULL) {
        die("packet buffer allocation");
    }

    struct pollfd sockets[2] = {
        {.fd = host_fd, .events = POLLIN},
        {.fd = peer_fd, .events = POLLIN},
    };

    for (;;) {
        if (poll(sockets, 2, -1) < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("poll");
        }

        int incoming_fd = (sockets[0].revents & POLLIN) ? host_fd : peer_fd;
        struct sockaddr_ll packet_address;
        socklen_t address_length = sizeof(packet_address);
        ssize_t received_length = recvfrom(
            incoming_fd, frame, MAX_FRAME - TRAILER_LEN, 0,
            (struct sockaddr *)&packet_address, &address_length);
        if (received_length <= 0) {
            continue;
        }

        if (packet_address.sll_pkttype == PACKET_OUTGOING) {
            continue;
        }

        int came_from_host = incoming_fd == host_fd;
        size_t frame_length = (size_t)received_length;
        int decrypt = !came_from_host;
        int result = transform_packet(frame, &frame_length, decrypt,
                                      (uint16_t)selected_port);
        if (result < 0) {
            fprintf(stderr,
                    "drop malformed packet or failed GCM authentication\n");
            continue;
        }

        memcpy(frame, came_from_host ? peer_mac : host_mac, ETH_ALEN);
        if (came_from_host) {
            send_frame(peer_fd, argv[6], frame, frame_length);
        } else {
            send_frame(host_fd, argv[5], frame, frame_length);
        }
    }
}
