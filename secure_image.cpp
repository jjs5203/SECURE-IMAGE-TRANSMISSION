// secure_image.cpp  (patched version)
//
// Improvements:
// - Robust base64 decode (handles padding and invalid chars safely)
// - Safer hex parser (ignores whitespace, validates pairs)
// - Debug prints (enable DEBUG=1 to see sizes and simple checks)
// - Same CLI as before: encrypt <image> <packet.json>  OR  decrypt <packet.json> <output.png>

#include <bits/stdc++.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace std;

#define DEBUG 1  // set to 1 for verbose debugging output, 0 to silence

/* ================================================================
   BASE64 IMPLEMENTATION (robust)
   ================================================================ */

static const string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

inline bool is_base64_char(char c) {
    return (isalnum((unsigned char)c) || c == '+' || c == '/');
}

string base64_encode(const vector<unsigned char> &bytes) {
    string ret;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    size_t in_len = bytes.size();
    size_t pos = 0;

    while (in_len--) {
        char_array_3[i++] = bytes[pos++];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] =
                ((char_array_3[0] & 0x03) << 4) +
                ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] =
                ((char_array_3[1] & 0x0f) << 2) +
                ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i != 0) {
        for (int j = i; j < 3; j++)
            char_array_3[j] = 0;

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] =
            ((char_array_3[0] & 0x03) << 4) +
            ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] =
            ((char_array_3[1] & 0x0f) << 2) +
            ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (int j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while (i++ < 3)
            ret += '=';
    }

    return ret;
}

vector<unsigned char> base64_decode(const string &encoded) {
    // Build reverse lookup table for base64 chars
    static int rev[256];
    static bool inited = false;
    if (!inited) {
        for (int i = 0; i < 256; ++i) rev[i] = -1;
        for (size_t i = 0; i < base64_chars.size(); ++i) rev[(unsigned char)base64_chars[i]] = (int)i;
        inited = true;
    }

    vector<unsigned char> ret;
    int val=0, valb=-8;
    for (size_t i = 0; i < encoded.size(); ++i) {
        unsigned char c = (unsigned char)encoded[i];
        if (c == '=') break; // padding: stop reading further base64 symbols, handle final block later
        int d = rev[c];
        if (d == -1) {
            // skip non-base64 whitespace, but if truly invalid char present, treat as error
            if (isspace(c)) continue;
            // invalid character in base64 -> return empty to indicate error
            return vector<unsigned char>();
        }
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            ret.push_back((unsigned char)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    // Handle trailing padding '=' characters if present to ensure correct extraction
    // The above loop stops at first '=', but there may be base64 bytes accumulated; this handles them.
    // If encoded ends with '=', the main loop breaks; but because we processed full 6-bit groups,
    // we already emitted bytes as they became available. No extra action required here.

    // Note: if encoded contained invalid chars, we returned empty vector above.
    return ret;
}

/* ================================================================
   FILE I/O
   ================================================================ */

vector<unsigned char> read_file_bytes(const string &path) {
    ifstream file(path, ios::binary);
    if (!file) throw runtime_error("Cannot open file: " + path);

    vector<unsigned char> data((istreambuf_iterator<char>(file)),
                               istreambuf_iterator<char>());
    return data;
}

void write_file_bytes(const string &path, const vector<unsigned char> &data) {
    ofstream file(path, ios::binary);
    if (!file) throw runtime_error("Cannot write file: " + path);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

/* ================================================================
   XOR (Lightweight Cipher)
   ================================================================ */

vector<unsigned char> xor_process(const vector<unsigned char> &data,
                                  const string &key)
{
    vector<unsigned char> out(data.size());
    for (size_t i = 0; i < data.size(); i++)
        out[i] = data[i] ^ (unsigned char)key[i % key.size()];
    return out;
}

/* ================================================================
   AES-CTR (OpenSSL 3.x compatible)
   ================================================================ */

bool aes_ctr_encrypt(const vector<unsigned char> &plaintext,
                     const vector<unsigned char> &key,
                     vector<unsigned char> &ciphertext,
                     vector<unsigned char> &iv_out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    const EVP_CIPHER *cipher = nullptr;
    if (key.size() == 16) cipher = EVP_aes_128_ctr();
    else if (key.size() == 24) cipher = EVP_aes_192_ctr();
    else if (key.size() == 32) cipher = EVP_aes_256_ctr();
    else { EVP_CIPHER_CTX_free(ctx); return false; }

    iv_out.resize(16);
    if (RAND_bytes(iv_out.data(), (int)iv_out.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key.data(), iv_out.data())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int outlen1 = 0;
    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(cipher));

    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen1,
                           plaintext.data(), (int)plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int outlen2 = 0;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen1, &outlen2)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext.resize(outlen1 + outlen2);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes_ctr_decrypt(const vector<unsigned char> &ciphertext,
                     const vector<unsigned char> &key,
                     const vector<unsigned char> &iv,
                     vector<unsigned char> &plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    const EVP_CIPHER *cipher = nullptr;
    if (key.size() == 16) cipher = EVP_aes_128_ctr();
    else if (key.size() == 24) cipher = EVP_aes_192_ctr();
    else if (key.size() == 32) cipher = EVP_aes_256_ctr();
    else { EVP_CIPHER_CTX_free(ctx); return false; }

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext.resize(ciphertext.size() + EVP_CIPHER_block_size(cipher));
    int outlen1 = 0;

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &outlen1,
                           ciphertext.data(), (int)ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int outlen2 = 0;
    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen1, &outlen2)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext.resize(outlen1 + outlen2);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

/* ================================================================
   SHA-256
   ================================================================ */

string sha256_hex(const vector<unsigned char> &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), (size_t)data.size());
    SHA256_Final(hash, &sha256);

    stringstream ss;
    ss << hex << nouppercase;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << setw(2) << setfill('0') << (int)(hash[i] & 0xff);

    return ss.str();
}

/* ================================================================
   HEX HELPERS (robust)
   ================================================================ */

static inline int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

string to_hex(const vector<unsigned char> &v) {
    stringstream ss;
    ss << hex << nouppercase;
    for (unsigned char b : v)
        ss << setw(2) << setfill('0') << (int)(b & 0xff);
    return ss.str();
}

vector<unsigned char> from_hex(const string &hexstr) {
    vector<unsigned char> out;
    out.reserve(hexstr.size() / 2);
    // iterate and collect only valid hex chars (ignore whitespace)
    string cleaned;
    cleaned.reserve(hexstr.size());
    for (char c : hexstr) {
        if (hexval(c) != -1) cleaned.push_back(c);
    }
    if (cleaned.size() % 2 != 0) {
        // odd length => invalid hex
        return vector<unsigned char>();
    }
    for (size_t i = 0; i + 1 < cleaned.size(); i += 2) {
        int hi = hexval(cleaned[i]);
        int lo = hexval(cleaned[i+1]);
        if (hi == -1 || lo == -1) return vector<unsigned char>();
        unsigned char byte = (unsigned char)((hi << 4) | lo);
        out.push_back(byte);
    }
    return out;
}

/* ================================================================
   SIMPLE JSON-LIKE PACKET (robust extractor)
   ================================================================ */

void write_packet_json(const string &path,
                       const string &payload_hex,
                       const string &cipher_hash,
                       const string &method,
                       const string &iv_hex,
                       const string &orig_sha)
{
    // write in binary mode to avoid CR/LF or BOM surprises
    ofstream f(path, ios::binary);
    if (!f) throw runtime_error("Cannot write packet: " + path);

    f <<
      "{\n"
      "  \"method\": \"" << method << "\",\n"
      "  \"payload_hex\": \"" << payload_hex << "\",\n"
      "  \"cipher_hash\": \"" << cipher_hash << "\",\n"
      "  \"iv_hex\": \"" << iv_hex << "\",\n"
      "  \"original_sha256\": \"" << orig_sha << "\"\n"
      "}\n";

    f.close();
}

// robust reader: reads whole file into a string then finds "key": "VALUE"
map<string,string> read_packet_json(const string &path) {
    ifstream f(path, ios::binary);
    if (!f) throw runtime_error("Cannot open packet: " + path);

    string content((istreambuf_iterator<char>(f)), istreambuf_iterator<char>());
    f.close();

    map<string,string> out;

    auto extract = [&](const string &key)->string {
        string pattern = "\"" + key + "\": \"";
        size_t pos = content.find(pattern);
        if (pos == string::npos) return string("");
        pos += pattern.size();
        size_t end = content.find("\"", pos); // finds the closing quote for this value
        if (end == string::npos) return string("");
        return content.substr(pos, end - pos);
    };

    out["method"] = extract("method");
    out["payload_hex"] = extract("payload_hex");
    out["cipher_hash"] = extract("cipher_hash");
    out["iv_hex"] = extract("iv_hex");
    out["original_sha256"] = extract("original_sha256");

    return out;
}

/* ================================================================
   MAIN PIPELINE
   ================================================================ */

int main(int argc, char** argv) {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    if (argc < 4) {
        cout << "Usage:\n";
        cout << "  encrypt <image> <packet.json>\n";
        cout << "  decrypt <packet.json> <output.png>\n";
        return 0;
    }

    string mode = argv[1];

    /* ------------------------------------------------------------
       ENCRYPT MODE
       ------------------------------------------------------------ */
    if (mode == "encrypt") {
        string infile = argv[2];
        string packetfile = argv[3];

        auto img_data = read_file_bytes(infile);
        if (DEBUG) cerr << "[DBG] original bytes: " << img_data.size() << "\n";
        string orig_sha = sha256_hex(img_data);

        string b64 = base64_encode(img_data);
        if (DEBUG) cerr << "[DBG] base64 length: " << b64.size() << "\n";

        vector<unsigned char> b64bytes(b64.begin(), b64.end());

        string xor_key = "simplekey123";
        auto after_xor = xor_process(b64bytes, xor_key);
        if (DEBUG) cerr << "[DBG] after_xor size: " << after_xor.size() << "\n";

        vector<unsigned char> aes_key(16);
        for (size_t i = 0; i < 16; i++)
            aes_key[i] = (unsigned char)xor_key[i % xor_key.size()];

        vector<unsigned char> ciphertext, iv;
        string method;

        if (aes_ctr_encrypt(after_xor, aes_key, ciphertext, iv)) {
            method = "XOR+AES-CTR";
            if (DEBUG) cerr << "[DBG] aes ciphertext size: " << ciphertext.size() << " iv size: " << iv.size() << "\n";
        } else {
            ciphertext = after_xor;
            method = "XOR-only";
            if (DEBUG) cerr << "[DBG] fallback to XOR-only ciphertext size: " << ciphertext.size() << "\n";
        }

        string payload_hex = to_hex(ciphertext);
        string cipher_hash = sha256_hex(ciphertext);
        string iv_hex = to_hex(iv);

        write_packet_json(packetfile, payload_hex, cipher_hash, method, iv_hex, orig_sha);

        cout << "Encryption complete. Packet saved to: " << packetfile << "\n";

        if (DEBUG) {
            cerr << "[DBG] packet.json written. payload_hex length: " << payload_hex.size() << " chars\n";
        }
    }

    /* ------------------------------------------------------------
       DECRYPT MODE
       ------------------------------------------------------------ */
    else if (mode == "decrypt") {
        string packetfile = argv[2];
        string outimg = argv[3];

        auto m = read_packet_json(packetfile);

        string payload_hex = m["payload_hex"];
        if (payload_hex.empty()) {
            cerr << "Packet missing payload_hex or unable to parse packet.\n";
            return 1;
        }

        auto ciphertext = from_hex(payload_hex);
        if (ciphertext.empty() && !payload_hex.empty()) {
            cerr << "Packet payload_hex invalid (non-hex or odd length).\n";
            return 1;
        }
        if (DEBUG) cerr << "[DBG] ciphertext bytes: " << ciphertext.size() << "\n";

        string expected_cipher_hash = m["cipher_hash"];
        string method = m["method"];
        string orig_sha = m["original_sha256"];
        auto iv = from_hex(m["iv_hex"]);
        if (DEBUG) cerr << "[DBG] iv bytes: " << iv.size() << " method: " << method << "\n";

        string verify = sha256_hex(ciphertext);
        if (verify != expected_cipher_hash) {
            cerr << "Ciphertext hash mismatch. File tampered or corrupted during write/read.\n";
            return 1;
        }

        string xor_key = "simplekey123";
        vector<unsigned char> aes_key(16);
        for (size_t i = 0; i < 16; i++)
            aes_key[i] = (unsigned char)xor_key[i % xor_key.size()];

        vector<unsigned char> after_aes;
        vector<unsigned char> decrypted_after_xor;

        if (method == "XOR+AES-CTR") {
            if (!aes_ctr_decrypt(ciphertext, aes_key, iv, after_aes)) {
                cerr << "AES decrypt failed.\n";
                return 1;
            }
            if (DEBUG) cerr << "[DBG] after_aes size: " << after_aes.size() << "\n";
            decrypted_after_xor = xor_process(after_aes, xor_key);
        } else {
            decrypted_after_xor = xor_process(ciphertext, xor_key);
        }

        if (DEBUG) cerr << "[DBG] decrypted_after_xor size: " << decrypted_after_xor.size() << "\n";

        string b64(decrypted_after_xor.begin(), decrypted_after_xor.end());
        if (DEBUG) cerr << "[DBG] base64 string length: " << b64.size() << "\n";

        auto raw = base64_decode(b64);
        if (raw.empty() && !b64.empty()) {
            cerr << "Base64 decode failed: possibly corrupted base64 or invalid characters.\n";
            return 1;
        }

        if (DEBUG) cerr << "[DBG] decoded raw bytes: " << raw.size() << "\n";

        write_file_bytes(outimg, raw);

        string recon_sha = sha256_hex(raw);

        cout << "Decryption complete. Image saved: " << outimg << "\n";
        cout << "Integrity check: " << (recon_sha == orig_sha ? "MATCH" : "MISMATCH") << "\n";
        if (DEBUG) {
            cerr << "[DBG] original sha (from packet): " << orig_sha << "\n";
            cerr << "[DBG] reconstructed sha: " << recon_sha << "\n";
        }
    }

    return 0;
}
