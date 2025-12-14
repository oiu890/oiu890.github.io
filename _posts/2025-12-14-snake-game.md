---
title: LNC - Snake Game
date: 2025-12-14 23:59:00 +0800
categories: [Writeups,LNC]
tags: [writeups,rev,LNC]
author: <oiu890>
description: Writeup for Snake Game rev from Lag and Crash 5.0
---

# Hi
Yep this is also a migrated writeup.  I will make new ones soon.

# Challenge Details
Challenge name: Snake Game  
Competition: LNC 5.0  
Category: Reversing    
Difficulty: Medium  
Points: ???  
Solves: ???   
Author: benwoo1110  

# Challenge description
Just a simple snake game from the nokia days with a special fruit.

# Files
[snake_game](/assets/downloads/snake_game)

# Solve
We are given a binary that lets you play a snake game when run. (the kind where you eat apples to increase your length/score)  
The goal of the game is to eat the Golden apple.

## Examining the code
As with most binaries, we can use a decompiler like Ghidra to generate C-like pseudocode for analysis.

Note I have renamed function/variable names for easier analysis.

### Main function
![main](/assets/images/snake_game/snake_main.png)
First we will be taking a look at this "main" function which starts the game.

"main" calls quite a few other functions to do stuff. By simply clicking around you should be able to figure out that the last function, "logic", is the one we have to use to find the flag.

### Logic function
![logic](/assets/images/snake_game/logic.png)
The logic function is quite long but if you read properly it calls 2 important functions, "make_gapple_and_key" and "decrypt".
The golden apple has a 1/100 chance of being created. The code then checks if you have eaten it and calls "decrypt", which uses the key to decrypt the flag.

### make_gapple_and_key
![gapple](/assets/images/snake_game/gapple.png)
The X and Y positions of the golden apple are determined by the rand() function. The X coord has range of 1-38, while the Y coord has a range of 1-18. "fill_key" is then called to create the key.

### fill_key
![key](/assets/images/snake_game/key.png)
The "fill_key" function tells us how the key is generated.
rand() is first seeded using the x_coord of the golden apple, then used to generate the first 5 characters of the key.
After that rand() is seeded again but this time using the y_coord of the golden apple. The last 5 characters of the key are then filled.

### decrypt
Now lets look at the "decrypt" function.
![decrypt](/assets/images/snake_game/decrypt.png)
We can see that a hardcoded array is being xored with the key that was created earlier. The code then prints the new array. However, as the key is different everytime, even if you win you might not be given the correct flag 😔

## Brute force
So how should we solve it?
Remember that the key is seeded using the X and Y coord of the golden apple. However, these coords have a small range of 38 and 18. This means there are only 684 possible keys!
We can simply brute force this :)
***Note that you need to run the code in linux to use glibc's rand***  
```python
import ctypes, ctypes.util

# load glibc rand/srand
libc = ctypes.CDLL(ctypes.util.find_library("c"))
libc.srand.argtypes = [ctypes.c_uint]
libc.rand.restype = ctypes.c_int

# hardcoded encrypted bytes from decrypt()
arr = bytes([
    0x14,0xbe,0x2f,0x89,0xf2,0xc5,0xfa,0x1c,0x43,0xdc,
    0x6b,0x9e,0x33,0xda,0xfe,0x87,0xf1,0x49,0x70,0xd9,
    0x28,0x80,0x09,0x8f,0xb5,0x8d,0xc2,0x5e,0x1b,0xd6,
    0x1c,0xc0,0x01,0x8a,0xbe,0xc3,0x9d
])

def gen_key_half(seed, count=5):
    libc.srand(seed)
    out = []
    for _ in range(count):
        r = libc.rand()
        a = r & 0xff
        if a >= 0x80:  # interpret as signed char
            a -= 0x100
        b = (r // 0xff) & 0xff
        if b >= 0x80:
            b -= 0x100
        out.append((a + b) & 0xff) 
    return out

def gen_key(seed1, seed2):
    return gen_key_half(seed1) + gen_key_half(seed2)

def decrypt_with(key):
    return bytes(c ^ key[i % 10] for i, c in enumerate(arr))

best = None
for s1 in range(1, 39):   # gappleX range
    for s2 in range(1, 19):  # gappleY range
        key = gen_key(s1, s2)
        dec = decrypt_with(key)
        score = sum(32 <= b < 127 for b in dec) / len(dec) #score for most english characters
        if best is None or score > best[0]:
            best = (score, s1, s2, key, dec)

score, seed1, seed2, key, flag = best
print(f'X used {seed1}, Y used {seed2}, key {key}, score {score}')
print("Decrypted bytes:", flag)
```



## Flag
LNC25{g0ld3n_a99le_appe4r3_r4nD0m1y}
