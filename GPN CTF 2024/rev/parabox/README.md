# GPN CTF 2024 – Parabox

- **Category:** Reverse Engineering
- **Points:** 500
- **Solves:** 1

This was a very fun (and extremely painful) GameBoy challenge from GPN CTF 2024. In the end, it only had 1 solve, which wasn't ours. We got incredibly close to solving it, but ultimately couldn't. It was primarily me and my teammate, `@HalfInchPunisher` from team `CyberSpace`, who dedicated a significant portion of the second day of the CTF to solving this.

Huge props to the challenge author for making such a fun challenge!

## Challenge

> [This game](https://www.patricksparabox.com/) looked real fun, unfortunately they did not support my platform. I wanted to play it anyway, so I built this small version myself. Some things went wrong (writing assembly is hard), but I'm sure you can win nonetheless.
> Go push some paraboxes!
>
> Author: Alkalem
>
> [parabox.tar.gz](handout/parabox.tar.gz)

## Setup

The challenge handout contained a folder that had 6 files,

```
└── parabox
    ├── Dockerfile
    ├── headless.patch
    ├── parabox.gbc
    ├── README.md
    ├── run
    └── server.py
```

From reading the `Dockerfile` and `server.py`, we discovered that the remote instance expects moves in the format of `UP, DOWN, LEFT, RIGHT, A, B, SELECT, START`. Additionally, it uses [gearboy](https://github.com/drhelius/Gearboy/), a GameBoy emulator, to process these inputs. A patch has also been applied to allow [gearboy](https://github.com/drhelius/Gearboy/) to run in a headless mode.

For local testing purposes, we opted to instead use [BGB](https://bgb.bircd.org/) as our emulator of choice, due to its easy setup, and having used it for GameBoy challenges before. Simply loading the `parabox.gbc` file into it, and pressing `Esc` to launch the debugger, was enough to get set up!

> We customized the key bindings so that pressing `A` on our keyboard will input `A` `(REDO)` in the game, and pressing `B` will input `B` `(UNDO)`, instead of the default bindings which mapped these keys differently.

## Scripting

Before starting our solution, we wrote two Python scripts: one to log our movements while playing the game and store them in a text file called `moves.txt`, in the format the remote expects them, and another to simulate those moves, to make working with the game easier.

```py
# read_keyboard.py
import sys
import keyboard

move_sequence = []


def on_key_event(event):
    if event.event_type == keyboard.KEY_DOWN and event.name in [
        "up",
        "down",
        "right",
        "left",
        "a",
        "b",
    ]:
        move_sequence.append(event.name)
        print(f"{event.name} key pressed")


keyboard.hook(on_key_event)

print("Press ESC to stop.")

keyboard.wait("esc")

file_path = sys.argv[1] if len(sys.argv) > 1 else "moves.txt"

with open(file_path, "w") as file:
    file.write("\n".join(move_sequence).upper())
    print(f"Final sequence of arrow key moves written to {file_path}.")
```

```py
# simulate_keystrokes.py
import sys
import time

import keyboard


def simulate_keystrokes(move_sequence, delay):
    for move in move_sequence:
        if move != "EOF" and not move.startswith("#"):
            print(move)
            keyboard.press(
                move.lower()
            )  # Uppercase 'B' was not detected by the emulator
            time.sleep(
                delay
            )  # Sleeps are necessary for the emulator to register the keypresses
            keyboard.release(move)
            time.sleep(delay)
        else:
            print(move)


def read_moves_from_file(file_name):
    with open(file_name, "r") as file:
        return [line.strip() for line in file if line.strip()]


def main():
    if len(sys.argv) < 2:
        raise ValueError("Please provide the file name as an argument.")

    speed = "fast" if len(sys.argv) < 3 else sys.argv[2]
    delay = 0.1 if speed == "slow" else 0.05

    print(
        f"Starting in 2 seconds... (Speed: {speed}, Delay: {delay * 2} seconds)"  # The delay is doubled when logging because sleep is called both before and after the keypress.
    )  # Wait for the user to switch to the game window
    time.sleep(2)
    move_sequence = read_moves_from_file(sys.argv[1])
    simulate_keystrokes(move_sequence, delay)


if __name__ == "__main__":
    main()
```

## Solving

### Intro

> The moves used for all the showcases in this writeup are using ones uploaded by the challenge author (@Alkalem) after the CTF ended. The same `moves.txt` is uploaded in it's entirety in this repository as well, in the `solution` directory. This can be used to replicate the solutions locally, along with `simulate_keystrokes.py`.

The game provides 3 intro levels, to get the player familiarized with the game. The objective of the game was pretty simple, you had to fulfil the level goals, usually by putting the golden coloured blocks in the correct positions, after which you could take the player to the winning tile. Below is a showcase of the solutions for the intro levels.

https://github.com/rex69420/ctf-writeups/assets/65942753/1fe49c68-e18d-4208-88e5-ee456ebb3778

---

### Parabox

> From here on out, the value of `time.sleep` (delay) between keystrokes in `simulate_keystrokes.py` is increased, to better showcase the moves.

The first main level, `Parabox`, was another simple one, simply demonstrating the use of the blue teleporters. The player had to use the teleporter to get to the winning tile. Below is a showcase of the solution.

https://github.com/rex69420/ctf-writeups/assets/65942753/caab131e-39af-4062-990b-1c5aeda89f51

---

### Impossible

The second main level, `Impossible`, was where the difficulty started to ramp up. The level seemed impossible, with the winning tile being outside the map. However, this is where we found the first bug in the level.

While trying to solve the level and spam moves, we noticed that after enough spamming, we could get the player to skip the level, but couldn't figure out why, until we loaded up the debugger. From what we understood, we could change the position of the win tile by spamming moves, and thus overflowing it, since the bounds of the move array were not properly configured.

The coordinates of the win tile were stored at `C279` in memory, and we noticed that whenever we moved, `C1FE` would get incremented, and once it went back to `01`, the winning square's position would be changed to the last move, as the game would overflow the position of the winning tile, with the last move from the moves array.

We can find out the values for the moves are -

- `0x10` - `RIGHT`
- `0x20` - `LEFT`
- `0x40` - `UP`
- `0x80` - `DOWN`

The number of moves is stored at `C200`, and the moves themselves are stored after that. Here is a video showcasing that behavior.

https://github.com/rex69420/ctf-writeups/assets/65942753/6551e87a-a2f6-431e-be8d-cef622d25036

So, we just need the last move to be one that we can reach. Below is a showcase of the level, along with the debugger.

https://github.com/rex69420/ctf-writeups/assets/65942753/c25fdc39-f249-47a1-8868-28c38358f8bc

---

### Small

The third main level, `Small`, was another simple one, with the player having to use both, the green, and the blue teleporters to fulfil the level goals and get to the winning tile. Below is a showcase of the solution.

> You might notice `# Extra moves to store optimal snapshot (stall more if necessary)` show up in the console along with the moves, and there are some extra moves at the end of the solution. These moves were used to initialize a bug which will be used and explained in the next level.

https://github.com/rex69420/ctf-writeups/assets/65942753/6cc0cdb1-f36c-43e5-87f0-542e1257e3f2

---

### Missing

#### Our Failed Approach

The fourth, and the most difficult level, `Missing`, was where we got stuck. We couldn't figure out how to solve the level, and ultimately couldn't. Our first approach is shown in this video, without abusing any bugs, and just trying to solve the level. Even after we put the gold blocks in the correct positions, we couldn't win the level.

https://github.com/rex69420/ctf-writeups/assets/65942753/ee8745a1-88a5-4708-b5a7-b1bbbfe7da12

As you can see, the gold blocks are in the correct positions, but the player can't win the level. We tried to debug the level, but couldn't figure out what was wrong. We ultimately tried opening a ticket with the challenge author, and were told this is expected behaviour. We thought we had to replicate the bug used to solve `Impossible`, but that didn't work either.

A few hours later of trying to wrap our heads around the Ghidra decompiled code, using [GhidraBoy](https://github.com/Gekkio/GhidraBoy) and the output from the BGB Debugger, my teammate discovered this.

![discord_screenshot](https://github.com/rex69420/ctf-writeups/assets/65942753/0de37980-debc-4c08-ab2b-248dc1b18e73)

He discovered that there was a **3rd map** in the level (1st one was the main map, 2nd one was the teleporter map), and our theory was that the player had to push some blocks into the third map as well to win the level. Taking a look at the win conditions for this level, confirmed that theory.

```c
struct Block {
  char correct_position;
  char map;
  char value; // ?
}
```

```c
{
    [0x06, 0, 0], // Player being on the Win tile in the main (1st) map
    [0x24, 1, 1], // The first gold block in the blue (2nd) map
    [0x25, 1, 1], // The second gold block in the blue (2nd) map
    [0x25, 1, 1], // The third gold block in the blue (2nd) map
    [0x04, 2, 1], // The first block in the green (3rd) map
    [0x07, 2, 1], // The second block in the green (3rd) map
}
```

We thought at this point that we had to abuse the `UNDO` and `REDO` commands to solve the level, but we couldn't figure out how to do that. This is also the point where we ran into a bug which was unintended behavior, causing the game to reset when interacting with the 2nd teleporter block.

https://github.com/rex69420/ctf-writeups/assets/65942753/66691d18-aa5d-4add-8374-141f6d989880

#### The Intended Solution

After the CTF ended, the challenge author disclosed the intended solution to the level, which was to use a bug in the `UNDO` command to solve the level. The `UNDO`(s) are not done backwards, but "the game loads a checkpoint from up to **32 moves** earlier and replays forward from there" (direct quote from the challenge author). The level is titled `Missing`, since it has goals that are impossible to reach without using the snapshots (using `UNDO/REDO`).

The player can access the third map/stage from the **level before** by loading a snapshot (thus the need for the extra levels from the previous level). The last problem is that the player needs one more box, which can also be solved by loading a snapshot from the level before. So, we can set up our snapshot by doing some extra moves in the `Small`, to fulfil the conditions of this level. Below is a showcase of the solution.

https://github.com/rex69420/ctf-writeups/assets/65942753/d00910bb-232b-458e-8529-691dfdf49073

---

### The Last Hurdle

> We solved this level without being able to solve `Missing`, since we figured out that setting the address `C279` to `FF`, lets you skip the level locally. **This is also showcased in the video.** We would have solved the entire challenge, if not for us missing the snapshot bug in the previous level.

The fifth, and last level, was another one that we **thought** we solved without using any bugs in the code. I discovered the fact that you could access the green room, by glitching through the blue room pretty fast accidentally (which apparently was the bug), but couldn't figure out how to leave it. After a while, I realised that I could simply move the green box to an area where I could easily exit it, then glitch into it after entering the blue teleporter. Below is a showcase of the solution.

https://github.com/rex69420/ctf-writeups/assets/65942753/8ccfb420-b5d7-4b92-a93e-82094400adfc

---

## You win

Simply inputting `DOWN` twice allowed you to win the level (shown in the previous recording), and submitting these moves to the remote, got you the flag. Below is a simple solve script to get the flag.

```py
# solve.py
from pwn import *

io = remote("the-final-countdown--shawn-mendes-3474.ctf.kitctf.de", "443", ssl=True)
data = open("moves.txt").read()
io.sendlineafter(b"EOF\n", data.encode())
io.interactive()

"""
You solved the challenge, here is your flag:
GPNCTF{p41n_70_d3v3l0p_h0p3fully_l355_p41n_70_50lv3_fd29a4b2833}
"""
```

---

Below is the full showcase of the solutions for all the levels.

https://github.com/rex69420/ctf-writeups/assets/65942753/f5677c77-4681-4f7d-a434-401f05d6c5e6

If you've made it this far, thank you for reading the writeup! I hope you enjoyed it as much as I did attempting to solve this challenge. If you have any questions, suggestions, or improvements, feel free to contact me at `@rex.sh` on Discord.
