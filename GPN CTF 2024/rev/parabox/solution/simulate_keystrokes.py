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
