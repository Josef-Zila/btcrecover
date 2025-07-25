/*
    MultiBit MD5 OpenCL kernel
    Performs the 3 MD5 iterations required for MultiBit wallet processing
    
    Expects:
    - Input buffer: passwords in inbuf format
    - Salt buffer: single salt in saltbuf format  
    - Output buffer: 48 bytes per password (key1 + key2 + iv)
*/

// Include buffer structs and MD5 functions are handled by compilation process

__kernel void multibit_md5_main(__global inbuf* inbuffer,
                                __global saltbuf* saltbuffer,
                                __global outbuf* outbuffer) {
    
    unsigned int idx = get_global_id(0);
    
    // Get password data
    __global word* password_words = inbuffer[idx].buffer;
    word password_len = inbuffer[idx].length;
    
    // Get salt data
    __global word* salt_words = saltbuffer->buffer;
    word salt_len = saltbuffer->length;
    
    // Convert to bytes for MD5 processing
    unsigned char password_bytes[256];
    unsigned char salt_bytes[16];
    
    // Extract password bytes from word buffer
    for(int i = 0; i < password_len; i++) {
        word w_idx = i / wordSize;
        word b_idx = i % wordSize;
        password_bytes[i] = (password_words[w_idx] >> (b_idx * 8)) & 0xFF;
    }
    
    // Extract salt bytes from word buffer  
    for(int i = 0; i < salt_len; i++) {
        word w_idx = i / wordSize;
        word b_idx = i % wordSize;
        salt_bytes[i] = (salt_words[w_idx] >> (b_idx * 8)) & 0xFF;
    }
    
    // Create working buffer for salted password
    unsigned char salted[256];
    
    // Copy password + salt
    for(int i = 0; i < password_len; i++) {
        salted[i] = password_bytes[i];
    }
    for(int i = 0; i < salt_len; i++) {
        salted[password_len + i] = salt_bytes[i];
    }
    
    // First MD5: hash(password + salt) -> key1
    unsigned int key1[4];
    hash_private((unsigned int*)salted, password_len + salt_len, key1);
    
    // Second MD5: hash(key1 + password + salt) -> key2
    unsigned char key1_salted[272]; // 16 + max password+salt
    // Copy key1 as bytes
    for(int i = 0; i < 16; i++) {
        key1_salted[i] = ((unsigned char*)key1)[i];
    }
    // Copy password + salt
    for(int i = 0; i < password_len + salt_len; i++) {
        key1_salted[16 + i] = salted[i];
    }
    
    unsigned int key2[4];
    hash_private((unsigned int*)key1_salted, 16 + password_len + salt_len, key2);
    
    // Third MD5: hash(key2 + password + salt) -> iv
    unsigned char key2_salted[272];
    // Copy key2 as bytes
    for(int i = 0; i < 16; i++) {
        key2_salted[i] = ((unsigned char*)key2)[i];
    }
    // Copy password + salt
    for(int i = 0; i < password_len + salt_len; i++) {
        key2_salted[16 + i] = salted[i];
    }
    
    unsigned int iv[4];
    hash_private((unsigned int*)key2_salted, 16 + password_len + salt_len, iv);
    
    // Store results in output buffer as bytes packed into words
    // Total: 48 bytes (16 + 16 + 16)
    __global word* output = outbuffer[idx].buffer;
    
    unsigned char result_bytes[48];
    
    // Copy key1, key2, iv as bytes
    for(int i = 0; i < 16; i++) {
        result_bytes[i] = ((unsigned char*)key1)[i];           // bytes 0-15
        result_bytes[16 + i] = ((unsigned char*)key2)[i];      // bytes 16-31  
        result_bytes[32 + i] = ((unsigned char*)iv)[i];        // bytes 32-47
    }
    
    // Pack bytes into words for output
    for(int i = 0; i < 48; i += wordSize) {
        word packed = 0;
        for(int j = 0; j < wordSize && (i + j) < 48; j++) {
            packed |= ((word)result_bytes[i + j]) << (j * 8);
        }
        output[i / wordSize] = packed;
    }
}