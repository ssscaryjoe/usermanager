# USER MANAGER PROGRAM(DOUBLES AS A CHATTING SYSTEM)
import getpass
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys

# Note: I did not realise the debugging print statement requirements until after most of the code
# To make it easier for debugging, and the assesor, I am making a universal debugging class
# to debug all objects, and classes including private attributes, and print them.
# i believe this is a better solution than adding print statements that are scattered
# since this is universal, is more readable, has all the information
# and shows better knowledge of object oriented programming
# I will write comments showing examples of what this was used to debug in the late code
# i may also use this function throughout the code in the debug comments everywhere to show examples
# of real use cases
# I will also label this with "DEBUGNOTE" to make it easier to find, in case you want to control f
# the following code is wrapped in triple quotes as a commend to activate and unactivate. Its excluded by default
# you will have to reactivate it to use the examples
# i will try to use triple quotes for all the code to seperate it from the comments about it so that
# the comments are not activated with the code
# complex version
"""
    def debug(self, obj):
        for attr in dir(obj):
            print(f"{attr}: {getattr(obj, attr)}")
"""
def has_admin_privileges():
    # check for Administrator on Windows or root on other supported systems
    if os.name == "nt":
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False


def start_as_admin():
    #NOTE: THIS FUNCTION IS NOT TESTED ON OTHER OS, ONLY WINDOWS
    # request operating-system administrator access for the protected data file
    if os.name == "nt":
        import ctypes
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            subprocess.list2cmdline(sys.argv),
            os.getcwd(),
            1
        )
        return result > 32

    sudo = shutil.which("sudo")
    if sudo:
        os.execvp(sudo, [sudo, sys.executable] + sys.argv)
    return False


def xor_encrypt(text, key):
    # XOR text bytes with a repeating password key and store them as hexadecimal.
    key_bytes = key.encode("utf-8")
    if not key_bytes:
        raise ValueError("The password key must not be empty.")
    text_bytes = text.encode("utf-8")
    encrypted = bytes(
        value ^ key_bytes[index % len(key_bytes)]
        for index, value in enumerate(text_bytes)
    )
    return encrypted.hex()


def xor_decrypt(encrypted_text, key):
    # Reverse the XOR operation using the same password key.
    key_bytes = key.encode("utf-8")
    if not key_bytes:
        raise ValueError("The password key must not be empty.")
    encrypted_bytes = bytes.fromhex(encrypted_text)
    decrypted = bytes(
        value ^ key_bytes[index % len(key_bytes)]
        for index, value in enumerate(encrypted_bytes)
    )
    return decrypted.decode("utf-8")


def hash_password(password, salt):
    # create a slow salted password hash for account login
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 200000
    )


# user class for standard accounts
# Class: User
# Purpose: Represents a standard account and its saved knowledge.
# Encapsulation: The password hash is private and checked through a method.
# Inheritance: Parent class of AdminUser, which adds administrator behavior.
class User:
    def __init__(self, username, password=None, password_salt=None, password_hash=None):
        self._username = username  # protected attribute
        self.__password_salt = password_salt or secrets.token_bytes(16)
        if isinstance(self.__password_salt, str):
            self.__password_salt = bytes.fromhex(self.__password_salt)
        if password_hash:
            if isinstance(password_hash, str):
                password_hash = bytes.fromhex(password_hash)
            self.__password_hash = password_hash
        else:
            self.__password_hash = hash_password(password, self.__password_salt)
        # legacy password is used only to migrate older knowledge records
        self._legacy_password = None
        self._knowledge = []  # protected list for knowledge items

    def get_username(self):
        # public method to safely view the protected username
        return self._username

    def check_password(self, pwd):
        # public method to check the password without saving it
        password_hash = hash_password(pwd, self.__password_salt)
        return hmac.compare_digest(self.__password_hash, password_hash)

    def add_knowledge(self, item):
        # add a piece of knowledge to this user's protected list
        self._knowledge.append(item)

    def get_knowledge(self):
        # public method to view this user's knowledge items
        return list(self._knowledge)

    def is_admin(self):
        # public method to check this user's account type
        return False

    def to_record(self, knowledge_key):
        # prepare this user's hashed password and knowledge for storage
        knowledge = []
        for item in self._knowledge:
            knowledge.append(item.to_record(knowledge_key))
        return {
            "password_salt": self.__password_salt.hex(),
            "password_hash": self.__password_hash.hex(),
            "admin": self.is_admin(),
            "knowledge": knowledge
        }


# admin user class that inherits from user
# Class: AdminUser
# Purpose: Represents an account that can manage users.
# Encapsulation: The administrator flag is private and checked by is_admin.
# Inheritance: Child of User so it reuses normal account data and behavior.
class AdminUser(User):
    def __init__(self, username, password=None, password_salt=None, password_hash=None):
        super().__init__(username, password, password_salt, password_hash)
        self.__is_admin = True  # private admin flag

    def is_admin(self):
        # public method to check this user's account type
        return self.__is_admin

    def remove_user(self, user_table, target_name):
        # remove a user from the hash table using their username
        if target_name in user_table and target_name != self.get_username():
            del user_table[target_name]
            return True
        return False


# class for a piece of stored information
# Class: KnowledgeItem
# Purpose: Represents XOR-protected text that can be shared with users or groups.
# Encapsulation: The content is private and is accessed through get_content.
# Inheritance: No custom parent or child class.
class KnowledgeItem:
    def __init__(self, title, content, shared_users=None, shared_groups=None):
        self._title = title  # protected title
        self.__content = content  # private content
        self._shared_users = shared_users or []
        self._shared_groups = shared_groups or []

    def get_content(self):
        # public method to access private content
        return self.__content

    def get_title(self):
        # public method to view the knowledge title
        return self._title

    def to_record(self, key):
        # save this knowledge item with its content XOR encoded.
        return {
            "title": self._title,
            "content": xor_encrypt(self.__content, key),
            "encrypted": True,
            "key_type": "admin_password_xor",
            "shared_users": self._shared_users,
            "shared_groups": self._shared_groups
        }

    @classmethod
    def from_record(cls, record, key):
        # load both older plaintext records and current XOR-encoded records.
        content = record["content"]
        if record.get("encrypted", False):
            content = xor_decrypt(content, key)
        return cls(
            record["title"],
            content,
            record.get("shared_users", []),
            record.get("shared_groups", [])
        )

    def share_with_user(self, username):
        # allow one user to view this knowledge item
        if username not in self._shared_users:
            self._shared_users.append(username)

    def share_with_group(self, group_name):
        # allow a group to view this knowledge item
        if group_name not in self._shared_groups:
            self._shared_groups.append(group_name)

    def can_be_seen_by(self, username, group_names):
        # check whether a user has been given access to this item
        for group_name in group_names:
            if group_name in self._shared_groups:
                return True
        return username in self._shared_users


# class to group multiple users together
# Class: Group
# Purpose: Collects users so knowledge can be shared with the group.
# Encapsulation: The member list is private and exposed as a copy.
# Inheritance: No custom parent or child class.
class Group:
    def __init__(self, name):
        self._name = name  # protected group name
        self.__members = []  # private list of members

    def add_member(self, user):
        # add a user to the private members list
        if user not in self.__members:
            self.__members.append(user)

    def get_members(self):
        # public method to view members
        return list(self.__members)

    def remove_member(self, username):
        # remove a user from the group by username
        self.__members = [
            user for user in self.__members
            if user.get_username() != username
        ]

    def get_name(self):
        # public method to view the group name
        return self._name


# Class: UserManager
# Purpose: Loads, saves, authenticates, and manages accounts and groups.
# Encapsulation: The storage path is protected; dictionaries hold the managed objects.
# Inheritance: No custom parent or child class.
class UserManager:
    def __init__(self, storage_path):
        if not has_admin_privileges():
            # only operating-system administrators can access the data file
            raise PermissionError("Run this program as Administrator or root.")
        self._storage_path = storage_path
        self.users = {}  # hash table of usernames and User objects
        self.groups = {}  # hash table of group names and Group objects
        self._knowledge_key = None
        self._pending_knowledge = {}
        self._prepare_storage()
        self._load_users()

    def _prepare_storage(self):
        # create the private directory before creating the user file
        directory = os.path.dirname(self._storage_path)
        os.makedirs(directory, exist_ok=True)
        if os.name == "nt":
            self._set_windows_permissions(directory, True)
            if os.path.exists(self._storage_path):
                self._set_windows_permissions(self._storage_path, False)
        else:
            os.chown(directory, 0, 0)
            os.chmod(directory, 0o700)
            if os.path.exists(self._storage_path):
                os.chown(self._storage_path, 0, 0)
                os.chmod(self._storage_path, 0o600)

    def _set_windows_permissions(self, path, is_directory):
        # DEBUGGING NOTE: this FUnction is only tested in windows, and may not work on other OS
        # only needed for 
        permission = "F"
        if is_directory:
            permission = "(OI)(CI)F"
        account = subprocess.run(
            ["whoami"],
            check=True,
            capture_output=True,
            text=True
        ).stdout.strip()
        subprocess.run(
            ["icacls", path, "/inheritance:r"],
            check=True,
            capture_output=True,
            text=True
        )
        subprocess.run(
            ["icacls", path, "/remove:g", account],
            check=True,
            capture_output=True,
            text=True
        )
        subprocess.run(
            ["icacls", path, "/remove:d", account],
            check=True,
            capture_output=True,
            text=True
        )
        subprocess.run(
            ["icacls", path, "/setowner", "*S-1-5-32-544"],
            check=True,
            capture_output=True,
            text=True
        )
        subprocess.run(
            [
                "icacls", path, "/grant:r",
                "*S-1-5-18:" + permission,
                "*S-1-5-32-544:" + permission
            ],
            check=True,
            capture_output=True,
            text=True
        )

    def _load_users(self):
        # load saved users into the hash table
        if not os.path.exists(self._storage_path):
            return
        with open(self._storage_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        for username, record in data.get("users", {}).items():
            user_class = AdminUser if record.get("admin", False) else User
            if "password_hash" in record:
                user = user_class(
                    username,
                    password_salt=record["password_salt"],
                    password_hash=record["password_hash"]
                )
            else:
                user = user_class(username, record["password"])
                user._legacy_password = record["password"]
            self._pending_knowledge[username] = record.get("knowledge", [])
            self.users[username] = user
            # DEBUGNOTE: Check a saved account and its knowledge after loading.
            """
            debugger.debug(user)
            """
        for group_name, member_names in data.get("groups", {}).items():
            group = Group(group_name)
            for username in member_names:
                if username in self.users:
                    group.add_member(self.users[username])
            self.groups[group_name] = group
            # DEBUGNOTE: Check that the saved group members loaded correctly.
            """
            debugger.debug(group)
            """

    def unlock_knowledge(self, admin, password):
        # use the verified admin password as the in-memory XOR key
        if not admin.is_admin() or not admin.check_password(password):
            return False
        self._knowledge_key = password
        for username, records in self._pending_knowledge.items():
            user = self.users[username]
            for record in records:
                if record.get("key_type") == "admin_password_xor":
                    key = password
                elif record.get("encrypted", False):
                    key = user._legacy_password
                    if key is None:
                        raise ValueError("Cannot migrate this knowledge item.")
                else:
                    key = None
                if key is None:
                    item = KnowledgeItem(
                        record["title"],
                        record["content"],
                        record.get("shared_users", []),
                        record.get("shared_groups", [])
                    )
                else:
                    item = KnowledgeItem.from_record(record, key)
                user.add_knowledge(item)
            user._legacy_password = None
        self._pending_knowledge = {}
        self._save_users()
        return True

    def _save_users(self):
        # save the hash table to the protected text file
        if self._knowledge_key is None:
            for user in self.users.values():
                if user.get_knowledge():
                    raise ValueError("Admin must unlock knowledge before saving.")
        data = {"users": {}, "groups": {}}
        for username, user in self.users.items():
            data["users"][username] = user.to_record(self._knowledge_key)
        for name, group in self.groups.items():
            member_names = []
            for user in group.get_members():
                member_names.append(user.get_username())
            data["groups"][name] = member_names
        with open(self._storage_path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
        if os.name == "nt":
            self._set_windows_permissions(self._storage_path, False)
        else:
            os.chown(self._storage_path, 0, 0)
            os.chmod(self._storage_path, 0o600)

    def add_user(self, username, password, is_admin=False):
        # add a user to the hash table and save the updated data
        username = username.strip()
        if not username or not password:
            raise ValueError("Username and password must not be empty.")
        if username in self.users:
            return False
        user_class = AdminUser if is_admin else User
        self.users[username] = user_class(username, password)
        self._save_users()
        return True

    def authenticate(self, username, password):
        # check the username and password without exposing the password
        user = self.users.get(username)
        if user and user.check_password(password):
            return user
        return None

    def remove_user(self, admin, target_name):
        # allow only an administrator to remove another user
        if not admin.is_admin():
            return False
        removed = admin.remove_user(self.users, target_name)
        if removed:
            for group in self.groups.values():
                group.remove_member(target_name)
            self._save_users()
        return removed

    def add_group(self, name):
        # add a group to the group hash table and save it
        name = name.strip()
        if not name or name in self.groups:
            return False
        self.groups[name] = Group(name)
        self._save_users()
        return True

    def add_group_member(self, group_name, username):
        # add an existing user to a group and save the change
        if group_name not in self.groups or username not in self.users:
            return False
        self.groups[group_name].add_member(self.users[username])
        # DEBUGNOTE: Check the group after adding a member.
        """
        debugger.debug(self.groups[group_name])
        """
        self._save_users()
        return True

    def share_knowledge(self, owner, item_number, share_type, recipient):
        # give a user or group access to one of the owner's knowledge items
        knowledge = owner.get_knowledge()
        if item_number < 1 or item_number > len(knowledge):
            return False
        item = knowledge[item_number - 1]
        if share_type == "user" and recipient in self.users:
            item.share_with_user(recipient)
        elif share_type == "group" and recipient in self.groups:
            item.share_with_group(recipient)
        else:
            return False
        # DEBUGNOTE: Check the sharing recipients saved on the knowledge item.
        """
        debugger.debug(item)
        """
        self._save_users()
        return True

    def get_visible_knowledge(self, user):
        # return knowledge owned by the user or shared with them
        visible = []
        username = user.get_username()
        group_names = []
        for name, group in self.groups.items():
            for member in group.get_members():
                if member.get_username() == username:
                    group_names.append(name)
                    break
        for owner_name, owner in self.users.items():
            for item in owner.get_knowledge():
                if owner is user or item.can_be_seen_by(username, group_names):
                    visible.append((owner_name, item))
        return visible

    def save(self):
        # save changes made to a user's knowledge
        self._save_users()


def add_knowledge_menu(user, manager):
    # let a logged-in user add or view their knowledge
    while True:
        print("\n1. Add knowledge")
        print("2. View knowledge")
        print("3. Share knowledge")
        print("4. Log out")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            title = input("Knowledge title: ").strip()
            content = input("Knowledge content: ")
            if not title or not content:
                print("Title and content must not be empty.")
            else:
                item = KnowledgeItem(title, content)
                user.add_knowledge(item)
                # DEBUGNOTE: Check a newly created knowledge item.
                """
                debugger.debug(item)
                """
                manager.save()
                print("Knowledge saved.")
        elif choice == "2":
            knowledge = manager.get_visible_knowledge(user)
            for owner_name, item in knowledge:
                if owner_name == user.get_username():
                    print("\n" + item.get_title() + " (your knowledge):")
                else:
                    print("\n" + item.get_title() + " (shared by " + owner_name + "):")
                print(item.get_content())
            if not knowledge:
                print("No knowledge is available.")
        elif choice == "3":
            knowledge = user.get_knowledge()
            if not knowledge:
                print("Add knowledge before sharing it.")
                continue
            for number, item in enumerate(knowledge, start=1):
                print(str(number) + ". " + item.get_title())
            try:
                item_number = int(input("Knowledge number to share: ").strip())
            except ValueError:
                print("Enter a valid knowledge number.")
                continue
            print("1. Share with a user")
            print("2. Share with a group")
            share_choice = input("Choose an option: ").strip()
            recipient = input("Username or group name: ").strip()
            share_type = "user" if share_choice == "1" else "group"
            if share_choice not in ("1", "2"):
                print("Choose 1 or 2.")
            elif manager.share_knowledge(user, item_number, share_type, recipient):
                print("Knowledge shared.")
            else:
                print("Knowledge item, user, or group was not found.")
        elif choice == "4":
            break
        else:
            print("Choose 1, 2, 3, or 4.")


def admin_menu(admin, manager):
    # let an administrator manage user accounts
    while True:
        print("\n1. List users")
        print("2. Add user")
        print("3. Remove user")
        print("4. List groups")
        print("5. Create group")
        print("6. Add user to group")
        print("7. Log out")
        print("8. Manage my knowledge")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            for username in sorted(manager.users):
                role = "admin" if manager.users[username].is_admin() else "user"
                print(username + " (" + role + ")")
        elif choice == "2":
            username = input("New username: ").strip()
            password = getpass.getpass("New password: ")
            if not username or not password:
                print("Username and password must not be empty.")
            elif manager.add_user(username, password):
                print("User added.")
            else:
                print("That username already exists.")
        elif choice == "3":
            target_name = input("Username to remove: ").strip()
            if manager.remove_user(admin, target_name):
                print("User removed.")
            else:
                print("User not found or you cannot remove your own account.")
        elif choice == "4":
            for name in sorted(manager.groups):
                member_names = []
                for user in manager.groups[name].get_members():
                    member_names.append(user.get_username())
                print(name + ": " + ", ".join(member_names))
            if not manager.groups:
                print("No groups have been created.")
        elif choice == "5":
            name = input("New group name: ").strip()
            if manager.add_group(name):
                print("Group created.")
            else:
                print("Group name must be new and not empty.")
        elif choice == "6":
            name = input("Group name: ").strip()
            username = input("Username to add: ").strip()
            if manager.add_group_member(name, username):
                print("User added to group.")
            else:
                print("Group or user not found.")
        elif choice == "7":
            break
        elif choice == "8":
            add_knowledge_menu(admin, manager)
        else:
            print("Choose 1, 2, 3, 4, 5, 6, 7, or 8.")


def main():
    # start the user manager and keep showing the main menu
    if not has_admin_privileges():
        if start_as_admin():
            return
        print("Administrator permission was not granted.")
        return
    folder = os.path.dirname(os.path.abspath(__file__))
    storage_path = os.path.join(folder, "private_folder", "passwords.txt")
    manager = UserManager(storage_path)
    # DEBUGGING NOTE: This code may not work if private_folder does not exist, untested. ALso if it does work it mahy create a folder.
    #also, doesnt work if read only 
    if not manager.users:
        print("Create the initial administrator account.")
        username = ""
        while not username:
            username = input("Administrator username: ").strip()
            if not username:
                print("Username must not be empty.")
        while True:
            password = getpass.getpass("Administrator password: ")
            confirmation = getpass.getpass("Confirm password: ")
            if password and password == confirmation:
                break
            print("Passwords must match and must not be empty.")
        manager.add_user(username, password, is_admin=True)
        manager.unlock_knowledge(manager.users[username], password)
        print("Administrator account created.")
    else:
        # Admin login unlocks shared knowledge for this program session.
        print("Log in as an administrator to unlock saved knowledge.")
        while True:
            username = input("Administrator username: ").strip()
            password = getpass.getpass("Administrator password: ")
            admin = manager.authenticate(username, password)
            if admin and admin.is_admin():
                manager.unlock_knowledge(admin, password)
                break
            print("Administrator username or password is incorrect.")

    while True:
        print("\n1. Log in")
        print("2. Quit")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            user = manager.authenticate(username, password)
            if user is None:
                print("Username or password is incorrect.")
            elif user.is_admin():
                admin_menu(user, manager)
            else:
                add_knowledge_menu(user, manager)
        elif choice == "2":
            print("Goodbye.")
            break
        else:
            print("Choose 1 or 2.")


if __name__ == "__main__":
    main()