#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "consts.h"
#include "io.h"
#include "libsecurity.h"

int state_sec = 0;     // Current state for handshake
char* hostname = NULL; // For client: storing inputted hostname
EVP_PKEY* priv_key = NULL;
tlv* client_hello = NULL;
tlv* server_hello = NULL;

uint8_t ts[1000] = {0};
uint16_t ts_len = 0;

bool inc_mac = false;  // For testing only: send incorrect MACs

void init_sec(int initial_state, char* host, bool bad_mac) {
    state_sec = initial_state;
    hostname = host;
    inc_mac = bad_mac;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");

        //Generate an ephemeral public/private key pair
        generate_private_key();
        derive_public_key();
        
        client_hello = create_tlv(CLIENT_HELLO);

        //generate nonce
        uint8_t nonce_data[NONCE_SIZE];
        generate_nonce(nonce_data, NONCE_SIZE);
        tlv* nonce = create_tlv(NONCE);
        add_val(nonce, nonce_data, NONCE_SIZE);
        add_tlv(client_hello,nonce);

        //add public key
        tlv* pub=create_tlv(PUBLIC_KEY);
        add_val(pub,public_key,pub_key_size);
        add_tlv(client_hello,pub);

        //Make sure to cache the entire Client Hello message-you’ll need it for another step.
        ts_len=serialize_tlv(ts,client_hello);

        //change state
        state_sec=CLIENT_SERVER_HELLO_AWAIT;

        return serialize_tlv(buf, client_hello);
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        //Generate an ephemeral public/private key pair
        generate_private_key();
        derive_public_key();
        
        EVP_PKEY* ephem_key=get_private_key();
        server_hello = create_tlv(SERVER_HELLO);

        //generate nonce
        uint8_t nonce_data[NONCE_SIZE];
        generate_nonce(nonce_data, NONCE_SIZE);
        tlv* nonce = create_tlv(NONCE);
        add_val(nonce, nonce_data, NONCE_SIZE);
        add_tlv(server_hello,nonce);
        //add certificate
        load_certificate("server_cert.bin");
        tlv*cert=deserialize_tlv(certificate,cert_size);
        add_tlv(server_hello,cert);
        //add public key
        tlv* pub=create_tlv(PUBLIC_KEY);
        add_val(pub,public_key, pub_key_size);
        add_tlv(server_hello,pub);

        uint8_t to_sign[2000];
        uint16_t offset = 0;
        memcpy(to_sign + offset, ts, ts_len); 
        offset+=ts_len; 
        offset+=serialize_tlv(to_sign+offset, nonce);
        offset+=serialize_tlv(to_sign+offset, cert);
        offset+=serialize_tlv(to_sign+offset, pub);
        load_private_key("server_key.bin");
        uint8_t sig[255];
        size_t sig_size=sign(sig,to_sign,offset);
        //add handshake
        tlv* hs_sig = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(hs_sig, sig, sig_size);
        add_tlv(server_hello, hs_sig);
    
        set_private_key(ephem_key);

        uint16_t sh_len = serialize_tlv(ts + ts_len, server_hello);
        derive_secret(); 
        derive_keys(ts, ts_len + sh_len);
        ts_len += sh_len;

        state_sec=SERVER_FINISHED_AWAIT;

        return serialize_tlv(buf,server_hello);
    }
    case CLIENT_FINISHED_SEND: {
        print("SEND FINISHED");
        
        uint8_t transcript_data[MAC_SIZE];
        hmac(transcript_data, ts, ts_len);

        tlv* transcript = create_tlv(TRANSCRIPT);
        add_val(transcript, transcript_data, MAC_SIZE);

        tlv* finished = create_tlv(FINISHED);
        add_tlv(finished, transcript);

        state_sec = DATA_STATE;

        return serialize_tlv(buf, finished);
    }
    case DATA_STATE: {
        uint8_t plaintext[943];
        ssize_t plain_len = input_io(plaintext, sizeof(plaintext));
        if (plain_len <= 0) {
            return 0;
        }

        uint8_t iv[IV_SIZE];
        uint8_t ciphertext[1024];
        size_t cipher_len = encrypt_data(iv, ciphertext, plaintext, plain_len);

        tlv* iv_tlv = create_tlv(IV);
        add_val(iv_tlv, iv, IV_SIZE);

        tlv* cipher_tlv = create_tlv(CIPHERTEXT);
        add_val(cipher_tlv, ciphertext, cipher_len);

        uint8_t mac_data[2000];
        uint16_t mac_offset = 0;
        mac_offset += serialize_tlv(mac_data + mac_offset, iv_tlv);
        mac_offset += serialize_tlv(mac_data + mac_offset, cipher_tlv);

        uint8_t mac_digest[MAC_SIZE];
        if (inc_mac) {
            hmac(mac_digest, mac_data, mac_offset);
            mac_digest[0] ^= 0xFF;
        } else {
            hmac(mac_digest, mac_data, mac_offset);
        }

        tlv* mac_tlv = create_tlv(MAC);
        add_val(mac_tlv, mac_digest, MAC_SIZE);

        tlv* data = create_tlv(DATA);
        add_tlv(data, iv_tlv);
        add_tlv(data, cipher_tlv);
        add_tlv(data, mac_tlv);

        uint16_t len = serialize_tlv(buf, data);
        free_tlv(data);
        
        return len;
    }
    default:
        return 0;
    }
}

void  output_sec(uint8_t* buf, size_t length) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        client_hello = deserialize_tlv(buf, length);
        //make sure client hello
        if (client_hello == NULL || client_hello->type != CLIENT_HELLO) {
        fprintf(stderr, "Error: Expected Client Hello\n");
        exit(6); 
        }

        memcpy(ts,buf,length);
        ts_len=length;

        tlv*client_pub=get_tlv(client_hello,PUBLIC_KEY);
        load_peer_public_key(client_pub->val, client_pub->length);

        state_sec=SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        print("RECV SERVER HELLO");
        server_hello = deserialize_tlv(buf, length);
        if (server_hello == NULL || server_hello->type != SERVER_HELLO) {
            fprintf(stderr, "Error: Expected Server Hello\n");
            exit(6);
        }

        tlv* cert = get_tlv(server_hello, CERTIFICATE);
        if (cert == NULL) {
            fprintf(stderr, "Error: No certificate in Server Hello\n");
            exit(1);
        }

        tlv* dns_name = get_tlv(cert, DNS_NAME);
        tlv* cert_pub_key = get_tlv(cert, PUBLIC_KEY);
        tlv* lifetime = get_tlv(cert, LIFETIME);
        tlv* cert_sig = get_tlv(cert, SIGNATURE);

        if (dns_name == NULL || cert_pub_key == NULL || lifetime == NULL || cert_sig == NULL) {
            fprintf(stderr, "Error: Malformed certificate\n");
            exit(1);
        }

        if (strcmp((char*)dns_name->val, hostname) != 0) {
            fprintf(stderr, "Error: DNS name mismatch\n");
            exit(2);
        }

        uint64_t not_before = 0, not_after = 0;
        for (int i = 0; i < 8; i++) {
            not_before = (not_before << 8) | lifetime->val[i];
            not_after = (not_after << 8) | lifetime->val[i + 8];
        }
        uint64_t current_time = (uint64_t)time(NULL);
        if (current_time < not_before || current_time > not_after) {
            fprintf(stderr, "Error: Certificate expired or not yet valid\n");
            exit(1);
        }

        uint8_t cert_data[2000];
        uint16_t cert_offset = 0;
        cert_offset += serialize_tlv(cert_data + cert_offset, dns_name);
        cert_offset += serialize_tlv(cert_data + cert_offset, cert_pub_key);
        cert_offset += serialize_tlv(cert_data + cert_offset, lifetime);

        load_ca_public_key("ca_public_key.bin");
        if (verify(cert_sig->val, cert_sig->length, cert_data, cert_offset, ec_ca_public_key) != 1) {
            fprintf(stderr, "Error: Certificate signature verification failed\n");
            exit(1);
        }

        tlv* server_nonce = get_tlv(server_hello, NONCE);
        tlv* server_pub_key = get_tlv(server_hello, PUBLIC_KEY);
        tlv* hs_sig = get_tlv(server_hello, HANDSHAKE_SIGNATURE);

        if (server_nonce == NULL || server_pub_key == NULL || hs_sig == NULL) {
            fprintf(stderr, "Error: Malformed Server Hello\n");
            exit(3);
        }

        uint8_t hs_data[3000];
        uint16_t hs_offset = 0;
        memcpy(hs_data + hs_offset, ts, ts_len);
        hs_offset += ts_len;
        hs_offset += serialize_tlv(hs_data + hs_offset, server_nonce);
        hs_offset += serialize_tlv(hs_data + hs_offset, cert);
        hs_offset += serialize_tlv(hs_data + hs_offset, server_pub_key);

        load_peer_public_key(cert_pub_key->val, cert_pub_key->length);
        if (verify(hs_sig->val, hs_sig->length, hs_data, hs_offset, ec_peer_public_key) != 1) {
            fprintf(stderr, "Error: Handshake signature verification failed\n");
            exit(3);
        }

        load_peer_public_key(server_pub_key->val, server_pub_key->length);
        derive_secret();

        uint16_t sh_len = length;
        memcpy(ts + ts_len, buf, sh_len);
        derive_keys(ts, ts_len + sh_len);
        ts_len += sh_len;

        state_sec = CLIENT_FINISHED_SEND;
        break;
    }
    case SERVER_FINISHED_AWAIT: {
        print("RECV FINISHED");
        tlv* finished = deserialize_tlv(buf, length);
        if (finished == NULL || finished->type != FINISHED) {
            fprintf(stderr, "Error: Expected Finished\n");
            exit(6);
        }

        tlv* transcript = get_tlv(finished, TRANSCRIPT);
        if (transcript == NULL) {
            fprintf(stderr, "Error: No transcript in Finished\n");
            exit(4);
        }

        uint8_t expected_transcript[MAC_SIZE];
        hmac(expected_transcript, ts, ts_len);

        if (memcmp(transcript->val, expected_transcript, MAC_SIZE) != 0) {
            fprintf(stderr, "Error: Transcript mismatch\n");
            exit(4);
        }

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        tlv* data = deserialize_tlv(buf, length);
        if (data == NULL || data->type != DATA) {
            fprintf(stderr, "Error: Expected Data\n");
            exit(6);
        }

        tlv* iv_tlv = get_tlv(data, IV);
        tlv* cipher_tlv = get_tlv(data, CIPHERTEXT);
        tlv* mac_tlv = get_tlv(data, MAC);

        if (iv_tlv == NULL || cipher_tlv == NULL || mac_tlv == NULL) {
            fprintf(stderr, "Error: Malformed Data message\n");
            exit(5);
        }

        uint8_t mac_data[2000];
        uint16_t mac_offset = 0;
        mac_offset += serialize_tlv(mac_data + mac_offset, iv_tlv);
        mac_offset += serialize_tlv(mac_data + mac_offset, cipher_tlv);

        uint8_t expected_mac[MAC_SIZE];
        hmac(expected_mac, mac_data, mac_offset);

        if (memcmp(mac_tlv->val, expected_mac, MAC_SIZE) != 0) {
            fprintf(stderr, "Error: MAC verification failed\n");
            exit(5);
        }

        uint8_t plaintext[1024];
        size_t plain_len = decrypt_cipher(plaintext, cipher_tlv->val, cipher_tlv->length, iv_tlv->val);

        output_io(plaintext, plain_len);
        free_tlv(data);
        break;
    }
    default:
        break;
    }
}