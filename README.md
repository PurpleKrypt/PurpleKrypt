<p align="center">
    <img  src="https://purplekrypt.github.io/imgs/PurpleKrypt_Logo_Name_36p.png"/>
</p>

<p align="center">
    <img src="https://purplekrypt.github.io/imgs/PurpleKrypt_GUI_1.png"/>
</p>

# PurpleKrypt

PurpleKrypt is an encryption tool for text and file encryption, utilizing the AES-256-GCM algorithm. It supports keyfiles and passwords via Argon2id key derivation.

For a more visually appealing and easier-to-navigate experience, visit the [PurpleKrypt official website](https://purplekrypt.github.io).

**License: [GNU GPLv3](LICENSE)**

<br/>

## **Documentation and Usage Guide**:
For detailed documentation and usage instructions on how to use PurpleKrypt, visit the [Documentation and Usage Guide](https://purplekrypt.github.io/docs/graphical/graphical.html).

<br/>

## Setting up PurpleKrypt:

Go to the latest release and download the archive for your operating system or architecture.  
For a smoother experience, use the [download page](https://purplekrypt.github.io/download.html).

> _No dependencies are required to run PurpleKrypt._  
> _The executables are designed to run out of the box, making them portable and easy to use without installation._

<br/>

### Instructions for *Windows*:
1. Extract the `.zip` file
2. To start the tool, open/run the `purplekrypt.bat` file
3.  Run the `create_desktop_shortcut.bat` to create a desktop shortcut with icon.

> Note: If you see any prompts preventing you from running the files, click "Run Anyway."
> The PurpleKrypt project is free from any malicious code. We prioritize your security and privacy.

<br/>

### Instructions for *Linux*:
1. Extract the `.zip` file
2. Give execution permission to `purplekrypt.sh`:
    ```bash
   chmod +x purplekrypt.sh
    ```
4. To run, execute `purplekrypt.sh`:
   ```bash
   ./purplekrypt.sh
   ```

6. To create desktop shortcut with icon, give execution permission to `create_desktop_shortcut.sh`:
    ```bash
    chmod +x create_desktop_shortcut.sh
    ```

8. To run, execute `create_desktop_shortcut.sh`:
   ```bash
   ./create_desktop_shortcut.sh
   ```

10. To run PurpleKrypt, double click on the newly created desktop shortcut.

> Note: If the shortcut doesn't launch, right-click it and select "Allow Launching" or a similar option.

<br/>

### **Instructions for *MacOS***:

1. Open Terminal:
   - Navigate to the `PurpleKrypt_vX.X.X_MacOS_x86_64` directory using the command:
     
     (Replace `/path/to/` with the actual path, e.g., `Downloads/PurpleKrypt_vX.X.X_MacOS_x86_64`)

     ```bash
     cd /path/to/PurpleKrypt_vX.X.X_MacOS_x86_64
     ```

2. Give Execution Permission:
   - Run the following commands in the terminal once you are in the `PurpleKrypt_vX.X.X_MacOS_x86_64` directory:
     
     [After the first command you may have to enter your login password]

     ```bash
     sudo xattr -rd com.apple.quarantine ../
     chmod -R +x purplekrypt.app
     ```
> The commands above will remove the quarantine flag from the program files so that macOS doesn't block it due to being downloaded from the internet, and then give execution permission to `purplekrypt.app`

3. Open the Application:
   - Double-click on `purplekrypt.app` to open it.

4. Grant Permissions (if prompted):
   - Click Allow or Open if macOS asks for permission.
   - If blocked, go to **System Preferences > Security & Privacy > Open Anyway.**



<br/>
