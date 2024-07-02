import os

def list_files():
    files = [
        "local_vulnerability_checker(terminal).py",
        "network_module(terminal).py",
        "online_vulnerability_checker(terminal).py",
        "packet_sniffer(terminal).py",
        "password_module(terminal).py"
    ]
    return files

def display_menu(files):
    print("Select a Python file to run:")
    for i, file in enumerate(files, start=1):
        print(f"{i}. {file}")

def get_user_choice(files):
    choice = input("Enter the number of the file you want to run: ")
    if choice.isdigit():
        choice = int(choice)
        if 1 <= choice <= len(files):
            return files[choice - 1]
    print("Invalid choice. Please try again.")
    return None

def run_file(filename):
    try:
        with open(filename) as file:
            exec(file.read(), globals())
    except Exception as e:
        print(f"Error running file: {e}")

def main():
    files = list_files()
    while True:
        display_menu(files)
        choice = get_user_choice(files)
        if choice:
            run_file(choice)
            break

if __name__ == "__main__":
    main()
