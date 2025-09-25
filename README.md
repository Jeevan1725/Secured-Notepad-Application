# Secured Notepad Application

A simple desktop notepad application built with Python and Tkinter that provides secure storage for user notes. The application features user authentication and encrypts all note content using AES before saving it to a MySQL database, ensuring user data privacy.

## Features

*   **User Authentication:** Secure sign-up and sign-in system for user management.
*   **Secure Password Storage:** User passwords are not stored in plaintext. They are hashed using **bcrypt** before being saved to the database.
*   **Content Encryption:** All notes are encrypted using **AES (Advanced Encryption Standard)** in CBC mode before being stored, ensuring the confidentiality of the content.
*   **Key Derivation:** A unique encryption key is derived for each user from their username using `bcrypt.kdf`.
*   **Full CRUD Functionality:**
    *   **Create & Save:** Write new notes and save them with a unique file name.
    *   **Load & Read:** Load and decrypt existing notes to view or edit them.
    *   **Edit:** Modify the content of an existing note and save the changes.
    *   **Delete:** Permanently remove a note from the database.
*   **File Management:** Users can view a list of all their saved notes.
*   **Graphical User Interface (GUI):** A user-friendly and intuitive interface built with Tkinter.

## Technologies Used

*   **Language:** Python 3
*   **GUI:** Tkinter
*   **Database:** MySQL
*   **Libraries:**
    *   `mysql-connector-python`: For connecting to and interacting with the MySQL database.
    *   `pycryptodome`: For implementing AES encryption and decryption.
    *   `bcrypt`: For secure password hashing and key derivation.

## Prerequisites

Before you begin, ensure you have the following installed:
*   Python 3.x
*   A running MySQL server instance.

## Installation and Setup

1.  **Clone the Repository:**
    ```
    git clone https://github.com/your-username/secured-notepad.git
    cd secured-notepad
    ```

2.  **Install Dependencies:**
    Install the required Python packages using the `requirements.txt` file.
    ```
    pip install -r requirements.txt
    ```

3.  **Database Configuration:**
    *   Make sure your MySQL server is running.
    *   Create a new database. The application is currently configured to use a database named `jeevan1`.
        ```
        CREATE DATABASE jeevan1;
        ```
    *   Update the database connection details in the `DatabaseConnection` class (`host`, `user`, `passwd`, `database`) to match your MySQL setup.

4.  **Run the Application:**
    Execute the main Python script to launch the application.
    ```
    python your_script_name.py
    ```

## Usage

1.  Launch the application.
2.  On the login screen, click **Sign Up** to create a new account.
3.  Fill in your details and click **Sign Up**.
4.  You will be returned to the login screen. Enter your new credentials and click **Sign In**.
5.  In the main notepad window:
    *   Enter a **File Name**.
    *   Write your content in the text area.
    *   Use the **Save**, **Load**, **Edit**, and **Delete** buttons to manage your notes.
    *   Click **Show Files** to see a list of your saved notes.
    *   Click **Logout** to return to the login screen.

## Security Note

This project is intended for educational purposes. The current implementation uses a static salt (`b'secure_salt_1234'`) for key derivation. For a production environment, it is highly recommended to generate a unique, random salt for each user and store it in the database alongside their user information to enhance security.
