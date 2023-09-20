// ========================================
// Padding Function
// ========================================

padding(m) {
    // Get message length in bits
    l = m.length() * 8;
    
    k = 448 % 512 - l - 1;

    // appendBits(sign, length)
    m = appendBits(1, 1);
    m = appendBits(0, k);

    // Append the length as a 64 bit block
    m = appendBits(0, 64);
    m = m ^ l;

    return m;
}

// ========================================
// Messaging Schedule
// ========================================

ROTL(n, val) {
    return val << n | val >> (n-32)
}

f(t, x, y, z) {
    if (t < 20)           { return Ch(x,y,z) }
    else if (20 < t < 40) { return Parity(x,y,z) }
    else if (40 < t < 60) { return Maj(x,y,z) }
    else                  { return Parity(x,y,z) }
}

K(t) {
    if (t < 20)           { return 0x5a827999 }
    else if (20 < t < 40) { return 0x6ed9eba1 }
    else if (40 < t < 60) { return 0x8f1bbcdc }
    else                  { return 0xca62c1d6 }
}

SHAHashComputation(mBlocks, H) {
    // mBlocks is the blocks of the message
    // H is a 2D array of Hashes

    n = mBlocks.size();

    for (int i = 1; i < n; i++) {
        // Step 1: Prepare W_t
        if (i < 16) {
            w = mBlocks[i];
        }
        else {
            w = ROTL(1, mBlocks[i]);
        }

        // Step 2: Initialize the 5 working variables
        a = H[i-1][0];
        b = H[i-1][1];
        c = H[i-1][2];
        d = H[i-1][3];
        e = H[i-1][4];

        // Step 3
        for (int t = 0; t < 80; t++) {
            temp = ROTL(5, a) + f(b,c,d) + e + K(t) + w;
            e = d;
            d = c;
            c = ROTL(30, b);
            b = a;
            a = temp;
        }

        // Step 4: Compute the ith intermediate hash value
        H[i][0] = a + H[i-1][0];
        H[i][1] = b + H[i-1][1];
        H[i][2] = c + H[i-1][2];
        H[i][3] = d + H[i-1][3];
        H[i][4] = e + H[i-1][4];
    }

    // Return completed hash
    return H[N][0] + H[N][1] + H[N][2] + H[N][3] + H[N][4];
}