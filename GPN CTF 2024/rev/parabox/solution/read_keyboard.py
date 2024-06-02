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
