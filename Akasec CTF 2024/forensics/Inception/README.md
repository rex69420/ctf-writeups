# Akasec CTF 2024 – Inception

- **Category:** Forensics
- **Points:** 490
- **Solves:** 9

## Challenge

> We fragmented a critical piece of information (the flag) into ten distinct segments. These segments were subsequently uploaded to a machine utilizing a containerization technology known as Docker. Is it feasible to recover and reassemble all the fragmented data?
>
> Author: samaqlo
>
> Attachment: [dump.tar.gz](https://we.tl/t-liiJG72uc9)

## Solution

This challenge was solved by me, and my teammate `@47gg` after the CTF ended. This challenge just required using `grep`/`find` to solve it. We were given a `tar.gz` file, which contained a linux filesystem dump. The flag was divided into 10 parts and scattered across the filesystem.

> Instead of `grep`, I opted to use a faster tool called [ripgrep (rg)](https://github.com/BurntSushi/ripgrep)  to solve this challenge.

### Part 1

This was one of the harder parts, since it was stored as "part 1" with spaces in the filename, which made it harder to grep.

```bash
└─$ rg -ai "part 1"
# ...
var/lib/docker/volumes/mariadb/_data/ib_logfile0
980: part 1 : AKASEC{
# ...
```

### Part 2

This part was stored in a docker image, but was simple to find.

```bash
└─$ find . -name "*part2*"
./var/lib/docker/overlay2/f400076fcbcfdeb39da0000038a8cf27ed34567e26a3825c395cb4fce88a122f/diff/tmp/part2
```

```bash
└─$ cat ./var/lib/docker/overlay2/f400076fcbcfdeb39da0000038a8cf27ed34567e26a3825c395cb4fce88a122f/diff/tmp/part2
H1ppO
```

### Part 3

This part was one of the easiest to find, and was stored in a hidden file named `.part3`.

```bash
└─$ find . -name "*part3*"
./home/kali/cor/.vol/.part3
```

```bash
└─$ cat ./home/kali/cor/.vol/.part3
p0t0mO_
```

### Part 4

This was the hardest part to find, as initially I was thrown off by mozilla firefox history, but eventually my teammate found it in one of the docker volumes, hidden as one of the wordpress posts.

```
└─$ rg --hiden -ai "part 4" # --hidden is required to search the .mozilla directory
# ...
home/kali/.mozilla/firefox/oaachdwj.default-esr/places.sqlite
https://astalha.42.fr/?p=6PART 4 – samaqloshop
# ...
```

Initially, we thought that was the flag, `samqloshop`, but it was not. Opening the sqlite file in `sqlite3`, we can see a reference in the `moz_places` table, which points to the wordpress post.

```
└─$ sqlite3 home/kali/.mozilla/firefox/oaachdwj.default-esr/places.sqlite
# ...
sqlite> SELECT * FROM moz_places;
# ...
24|https://astalha.42.fr/?p=6|PART 4 – samaqloshop|rf.24.ahlatsa.|1|0|0|98|1717878675163234|1GwxqegMjA8k|0|47357721787285||||7|0||1
```

This led us to finding the wordpress post in the docker volume, which contained the flag.

```
└─$ rg -ai "PART 4" -A 1
./var/lib/docker/volumes/mariadb/_data/WORDPRESS/wp_posts.ibd
# ...
103-<p>NsTros</p>
104:<!-- /wp:paragraph -->PART 4
# ...
```

### Part 5

This part was also stored in a docker image, and was simple to find.

```bash
└─$ find . -name "*part5"
./var/lib/docker/overlay2/349dc3820066df85e6305ced2b0bb82401e7d1a279ace54fb5115645a006147c/diff/tmp/part5
```

```bash
└─$ cat ./var/lib/docker/overlay2/349dc3820066df85e6305ced2b0bb82401e7d1a279ace54fb5115645a006147c/diff/tmp/part5
EsquIp
```

### Part 6

This part was interesting, as it was stored in a binary file named `part6`

```bash
└─$ find . -name "*part6*"
./var/lib/docker/overlay2/d4cf4f90c3094b5942166f441d7c4e2514a55d0bb732d44776c8892b06252550/diff/part6/part6
```

```
└─$ file part6
part6: Mach-O 64-bit x86_64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
```

Putting this into [dogbolt.org](https://dogbolt.org/?id=2c2b9a65-c731-4eaa-943a-c9ec6242da5c), we can see from the `BinaryNinja` output, that the flag is stored in the binary.

```c
int64_t _main()
{
    char var_f;
    __builtin_strncpy(&var_f, "Edal1 ", 7); // flag
    return 0;
}
```

### Part 7

This was another simple one, but for some reason was encoded in base64 which threw us off for a while.

```bash
└─$ find . -name "*part7*"
./home/kali/Desktop/.part7
```

```bash
└─$ cat ./home/kali/Desktop/.part7 | base64 -d
0pHOBI
```

### Part 8

This part was the name of one of the networks in docker.

```bash
└─$ rg -ai part8
var/lib/docker/network/files/local-kv.db
# ...
5: "name":"part8AtheRApEut"
# ...
```

### Part 9

This was stored as the name of a folder in the docker volumes directory.

```bash
└─$ find . -name "*part9*"
./var/lib/docker/volumes/part91cAliz
```

### Part 10

This was stored on the desktop of the user `kali`.

```bash
└─$ find . -name "*part_10*"
./home/kali/Desktop/this_is_the_part_10
```

```bash
└─$ cat ./home/kali/Desktop/this_is_the_part_10
At10nist1C}
```

### Flag

Combining all the parts, we can get the final flag, which was `AKASEC{H1ppOp0t0mO_NsTrosEsquIpEdal10pHOBIAtheRApEut1cAlizAt10nist1C}`.
