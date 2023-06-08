#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#define PORT 443
#define FILENAME "received_file.txt"

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
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Binding error");
        return -1;
    }

    if (listen(server_sock, 1) < 0) {
        perror("Listening error");
        return -1;
    }

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_sock < 0) {
        perror("Accept error");
        return -1;
    }

    // Wrap the socket with SSL/TLS
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL *ssl = SSL_new(ctx);
    BIO *bio = BIO_new_socket(client_sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);

    if (SSL_accept(ssl) != 1) {
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

    unsigned char *server_public_key = NULL;
    unsigned char *shared_secret = NULL;
    size_t server_public_key_len = 0;
    size_t shared_secret_len = 0;

    if (OQS_KEM_keypair(kyber_kem, &server_public_key, &shared_secret) != OQS_SUCCESS) {
        fprintf(stderr, "Kyber keypair generation failed\n");
        return -1;
    }

    // Receive client public key from the client
    unsigned char client_public_key[OQS_KEM_PUBLIC_KEY_BYTES];
    if (SSL_read(ssl, client_public_key, OQS_KEM_PUBLIC_KEY_BYTES) <= 0) {
        fprintf(stderr, "Failed to receive client public key\n");
        return -1;
    }

    // Send server public key to the client
    if (SSL_write(ssl, server_public_key, OQS_KEM_PUBLIC_KEY_BYTES) <= 0) {
        fprintf(stderr, "Failed to send server public key\n");
        return -1;
    }

    // Perform key encapsulation with Kyber
    unsigned char encapsulated_key[OQS_KEM_BYTES];
    if (OQS_KEM_encaps(kyber_kem, encapsulated_key, shared_secret, client_public_key) != OQS_SUCCESS) {
        fprintf(stderr, "Kyber encapsulation failed\n");
        return -1;
    }

    // Receive encapsulated key from the client
    unsigned char client_encapsulated_key[OQS_KEM_BYTES];
    if (SSL_read(ssl, client_encapsulated_key, OQS_KEM_BYTES) <= 0) {
        fprintf(stderr, "Failed to receive encapsulated key\n");
        return -1;
    }

    // Perform key decapsulation with Kyber
    unsigned char client_shared_secret[OQS_KEM_SHARED_SECRET_BYTES];
    if (OQS_KEM_decaps(kyber_kem, client_shared_secret, client_encapsulated_key, server_public_key) != OQS_SUCCESS) {
        fprintf(stderr, "Kyber decapsulation failed\n");
        return -1;
    }

    // Verify shared secret match
    if (memcmp(shared_secret, client_shared_secret, OQS_KEM_SHARED_SECRET_BYTES) != 0) {
        fprintf(stderr, "Shared secret mismatch\n");
        return -1;
    }

    // Cleanup
    OQS_KEM_free(kyber_kem);
    OQS_MEM_secure_free(server_public_key, OQS_KEM_PUBLIC_KEY_BYTES);
    OQS_MEM_secure_free(shared_secret, OQS_KEM_SHARED_SECRET_BYTES);

    // Receive the file from the client
    FILE *file = fopen(FILENAME, "wb");
    if (!file) {
        perror("File open error");
        return -1;
    }

    char buffer[1024];
    ssize_t bytes_read;
    while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, sizeof(char), bytes_read, file);
    }

    fclose(file);

    // Close the SSL/TLS connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    // Close the client socket
    close(client_sock);

    // Close the server socket
    close(server_sock);

    // Cleanup OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    // Clean up the OQS library
    OQS_cleanup();

    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#define PORT 443
#define FILENAME "received_file.txt"

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
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Binding error");
        return -1;
    }

    if (listen(server_sock, 1) < 0) {
        perror("Listening error");
        return -1;
    }

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_sock < 0) {
        perror("Accept error");
        return -1;
    }

    // Wrap the socket with SSL/TLS
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL *ssl = SSL_new(ctx);
    BIO *bio = BIO_new_socket(client_sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);

    if (SSL_accept(ssl) != 1) {
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

    unsigned char *server_public_key = NULL;
    unsigned char *shared_secret = NULL;
    size_t server_public_key_len = 0;
    size_t shared_secret_len = 0;

    if (OQS_KEM_keypair(kyber_kem, &server_public_key, &shared_secret) != OQS_SUCCESS) {
        fprintf(stderr, "Kyber keypair generation failed\n");
        return -1;
    }

    // Receive client public key from the client
    unsigned char client_public_key[OQS_KEM_PUBLIC_KEY_BYTES];
    if (SSL_read(ssl, client_public_key, OQS_KEM_PUBLIC_KEY_BYTES) <= 0) {
        fprintf(stderr, "Failed to receive client public key\n");
        return -1;
    }

    // Send server public key to the client
    if (SSL_write(ssl, server_public_key, OQS_KEM_PUBLIC_KEY_BYTES) <= 0) {
        fprintf(stderr, "Failed to send server public key\n");
        return -1;
    }

    // Perform key encapsulation with Kyber
    unsigned char encapsulated_key[OQS_KEM_BYTES];
    if (OQS_KEM_encaps(kyber_kem, encapsulated_key, shared_secret, client_public_key) != OQS_SUCCESS) {
        fprintf(stderr, "Kyber encapsulation failed\n");
        return -1;
    }

    // Receive encapsulated key from the client
    unsigned char client_encapsulated_key[OQS_KEM_BYTES];
    if (SSL_read(ssl, client_encapsulated_key, OQS_KEM_BYTES) <= 0) {
        fprintf(stderr, "Failed to receive encapsulated key\n");
        return -1;
    }

    // Perform key decapsulation with Kyber
    unsigned char client_shared_secret[OQS_KEM_SHARED_SECRET_BYTES];
    if (OQS_KEM_decaps(kyber_kem, client_shared_secret, client_encapsulated_key, server_public_key) != OQS_SUCCESS) {
        fprintf(stderr, "Kyber decapsulation failed\n");
        return -1;
    }

    // Verify shared secret match
    if (memcmp(shared_secret, client_shared_secret, OQS_KEM_SHARED_SECRET_BYTES) != 0) {
        fprintf(stderr, "Shared secret mismatch\n");
        return -1;
    }

    // Cleanup
    OQS_KEM_free(kyber_kem);
    OQS_MEM_secure_free(server_public_key, OQS_KEM_PUBLIC_KEY_BYTES);
    OQS_MEM_secure_free(shared_secret, OQS_KEM_SHARED_SECRET_BYTES);

    // Receive the file from the client
    FILE *file = fopen(FILENAME, "wb");
    if (!file) {
        perror("File open error");
        return -1;
    }

    char buffer[1024];
    ssize_t bytes_read;
    while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, sizeof(char), bytes_read, file);
    }

    fclose(file);

    // Close the SSL/TLS connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    // Close the client socket
    close(client_sock);

    // Close the server socket
    close(server_sock);

    // Cleanup OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    // Clean up the OQS library
    OQS_cleanup();

    return 0;
}
