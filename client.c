#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#define HOST "server_ip_address"
#define PORT 443
#define FILENAME "file.txt"

int main() {
    // Initialize the OQS library
    OQS_STATUS rc = OQS_SUCCESS;
    if (OQS_SUCCESS != (rc = OQS_init())) {
        fprintf(stderr, "OQS initialization failed with error code %d\n", rc);
        return -1;
    }

    // Load the Dillithium and Kyber post-quantum algorithms
    if (OQS_SUCCESS != (rc = OQS_crypto_register_all())) {
        fprintf(stderr, "OQS algorithm registration failed with error code %d\n", rc);
        return -1;
    }

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    // Create a TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(HOST);
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection error");
        return -1;
    }

    // Wrap the socket with SSL/TLS
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    BIO *bio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);

    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "SSL connection error\n");
        return -1;
    }

    // Perform key exchange using Kyber
    const char *kyber_kem_name = "kyber512";
    const OQS_KEM *kyber_kem = OQS_KEM_new(kyber_kem_name);
    if (kyber_kem == NULL) {
        fprintf(stderr, "Failed to initialize Kyber\n");
        return -1;
    }

    unsigned char *client_public_key = NULL;
    unsigned char *shared_secret = NULL;
    size_t client_public_key_len = 0;
    size_t shared_secret_len = 0;

    if (OQS_KEM_keypair(kyber_kem, &client_public_key, &shared_secret) != OQS_SUCCESS) {
        fprintf(stderr, "Kyber keypair generation failed\n");
        return -1;
    }

    // Send client public key to the server
    if (SSL_write(ssl, client_public_key, OQS_KEM_PUBLIC_KEY_BYTES) <= 0) {
        fprintf(stderr, "Failed to send client public key\n");
        return -1;
    }

    // Receive server public key from the server
    unsigned char server_public_key[OQS_KEM_BYTES];
    if (SSL_read(ssl, server_public_key, OQS_KEM_PUBLIC_KEY_BYTES) <= 0) {
        fprintf(stderr, "Failed to receive server public key\n");
        return -1;
    }

    // Perform key encapsulation with Kyber
    unsigned char encapsulated_key[OQS_KEM_BYTES];
    if (OQS_KEM_encaps(kyber_kem, encapsulated_key, shared_secret, server_public_key) != OQS_SUCCESS) {
        fprintf(stderr, "Kyber encapsulation failed\n");
        return -1;
    }

    // Send encapsulated key to the server
    if (SSL_write(ssl, encapsulated_key, OQS_KEM_BYTES) <= 0) {
        fprintf(stderr, "Failed to send encapsulated key\n");
        return -1;
    }

    // Receive encapsulated key from the server
    unsigned char server_encapsulated_key[OQS_KEM_BYTES];
    if (SSL_read(ssl, server_encapsulated_key, OQS_KEM_BYTES) <= 0) {
        fprintf(stderr, "Failed to receive encapsulated key\n");
        return -1;
    }

    // Perform key decapsulation with Kyber
    unsigned char server_shared_secret[OQS_KEM_SHARED_SECRET_BYTES];
    if (OQS_KEM_decaps(kyber_kem, server_shared_secret, server_encapsulated_key, client_public_key) != OQS_SUCCESS) {
        fprintf(stderr, "Kyber decapsulation failed\n");
        return -1;
    }

    // Verify shared secret match
    if (memcmp(shared_secret, server_shared_secret, OQS_KEM_SHARED_SECRET_BYTES) != 0) {
        fprintf(stderr, "Shared secret mismatch\n");
        return -1;
    }

    // Cleanup
    OQS_KEM_free(kyber_kem);
    OQS_MEM_secure_free(client_public_key, OQS_KEM_PUBLIC_KEY_BYTES);
    OQS_MEM_secure_free(shared_secret, OQS_KEM_SHARED_SECRET_BYTES);

    // Send the file to the server
    FILE *file = fopen(FILENAME, "rb");
    if (!file) {
        perror("File open error");
        return -1;
    }

    char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, sizeof(char), sizeof(buffer), file)) > 0) {
        if (SSL_write(ssl, buffer, bytes_read) <= 0) {
            fprintf(stderr, "Failed to send file\n");
            fclose(file);
            return -1;
        }
    }

    fclose(file);

    // Close the SSL/TLS connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    // Cleanup OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    // Close the socket
    close(sock);

    // Clean up the OQS library
    OQS_cleanup();

    return 0;
}
